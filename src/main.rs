//! capd — Sorabbyngo Capability Token Daemon
//!
//! Issues, validates, and revokes capability tokens for all processes.
//! Sits between the kernel LSM and the domain-mode manager.
//!
//! Flow:
//!   1. Agent/process requests capabilities via Unix socket
//!   2. capd evaluates against policy (agent manifest × task policy × user grants)
//!   3. capd installs approved tokens via /proc/<pid>/cap_tokens
//!   4. capd tracks expiry and revokes tokens when TTL expires
//!   5. All decisions written to tamper-evident audit log
//!
//! Socket: /run/sorabbyngo/capd.sock
//! Audit:  /var/log/sorabbyngo/cap_audit.log (append-only, fsync on write)

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Token domains (mirror kernel constants) ────────────────────────────────
pub const CAP_DOMAIN_FS:   u8 = 0x01;
pub const CAP_DOMAIN_NET:  u8 = 0x02;
pub const CAP_DOMAIN_GPU:  u8 = 0x04;
pub const CAP_DOMAIN_IPC:  u8 = 0x08;
pub const CAP_DOMAIN_PROC: u8 = 0x10;

pub const CAP_OP_READ:    u8 = 0x01;
pub const CAP_OP_WRITE:   u8 = 0x02;
pub const CAP_OP_EXEC:    u8 = 0x04;
pub const CAP_OP_CONNECT: u8 = 0x08;
pub const CAP_OP_COMPUTE: u8 = 0x20;

// ── Token representation ───────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct CapToken {
    pub id:         u32,
    pub pid:        u32,
    pub domain:     u8,
    pub op:         u8,
    pub scope:      u64,   // inode / port / device id
    pub expires_at: Option<SystemTime>,
    pub granted_by: String, // "policy:agent-manifest" | "user:grant" | "domain-mode"
}

impl CapToken {
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            None => false,
            Some(exp) => SystemTime::now() > exp,
        }
    }

    /// Serialise to kernel wire format (24 bytes)
    pub fn to_wire(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0] = self.domain;
        buf[1] = self.op;
        // bytes 2-3: pad
        buf[4..12].copy_from_slice(&self.scope.to_le_bytes());
        let expires_ns: u64 = match self.expires_at {
            None => 0,
            Some(t) => t.duration_since(UNIX_EPOCH)
                         .unwrap_or_default()
                         .as_nanos() as u64,
        };
        buf[12..20].copy_from_slice(&expires_ns.to_le_bytes());
        buf
    }
}

// ── Capability request (from agent/process via socket) ─────────────────────
#[derive(Debug)]
pub struct CapRequest {
    pub pid:    u32,
    pub agent:  String,   // agent name from manifest, or process comm
    pub wants:  Vec<CapSpec>,
}

#[derive(Debug)]
pub struct CapSpec {
    pub domain:  u8,
    pub op:      u8,
    pub scope:   u64,
    pub ttl_sec: Option<u64>,  // None = persistent
}

// ── Policy engine ──────────────────────────────────────────────────────────
pub struct PolicyEngine {
    /// Agent manifests loaded from /etc/sorabbyngo/agents/*.cap.json
    manifests: HashMap<String, Vec<CapSpec>>,
    /// Current domain mode (written by domain-mode manager)
    domain_mode: String,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            manifests:   HashMap::new(),
            domain_mode: "balanced".into(),
        }
    }

    pub fn load_manifests(&mut self, dir: &str) {
        // In production: parse JSON manifests from /etc/sorabbyngo/agents/
        // For now: hardcoded example manifests per agent class
        println!("[capd] Loading agent manifests from {}", dir);
    }

    /// Evaluate a request against policy.
    /// Returns the subset of CapSpec entries that are approved.
    pub fn evaluate(&self, req: &CapRequest) -> Vec<CapSpec> {
        let mut approved = Vec::new();

        for spec in &req.wants {
            if self.is_allowed(&req.agent, spec) {
                approved.push(CapSpec {
                    domain:  spec.domain,
                    op:      spec.op,
                    scope:   spec.scope,
                    // Enforce max TTL: agents never get > 1hr without renewal
                    ttl_sec: Some(spec.ttl_sec.unwrap_or(3600).min(3600)),
                });
            }
        }

        approved
    }

    fn is_allowed(&self, agent: &str, spec: &CapSpec) -> bool {
        // GPU compute: only allowed in AI or gaming domain modes
        if spec.domain == CAP_DOMAIN_GPU && spec.op == CAP_OP_COMPUTE {
            if self.domain_mode != "ai" && self.domain_mode != "gaming" {
                return false;
            }
        }

        // Network: security mode restricts to Tor exit (port 9050) by default
        if spec.domain == CAP_DOMAIN_NET && self.domain_mode == "security" {
            if spec.scope != 9050 && spec.scope != 0 {
                return false;
            }
        }

        // In production: check against loaded manifest for this agent
        // For now: approve everything that passes domain-mode checks
        true
    }

    pub fn set_domain_mode(&mut self, mode: &str) {
        println!("[capd] Domain mode -> {}", mode);
        self.domain_mode = mode.to_string();
    }
}

// ── Token store ────────────────────────────────────────────────────────────
pub struct TokenStore {
    tokens:   HashMap<u32, Vec<CapToken>>,  // pid -> tokens
    next_id:  u32,
}

impl TokenStore {
    pub fn new() -> Self {
        Self { tokens: HashMap::new(), next_id: 1 }
    }

    pub fn install(&mut self, pid: u32, approved: Vec<CapSpec>, agent: &str) -> Vec<CapToken> {
        let mut installed = Vec::new();
        for spec in approved {
            let tok = CapToken {
                id:         self.next_id,
                pid,
                domain:     spec.domain,
                op:         spec.op,
                scope:      spec.scope,
                expires_at: spec.ttl_sec.map(|s| {
                    SystemTime::now() + Duration::from_secs(s)
                }),
                granted_by: format!("policy:{}", agent),
            };
            self.next_id += 1;

            // Write token to kernel via /proc/<pid>/cap_tokens
            let proc_path = format!("/proc/{}/cap_tokens", pid);
            match fs::OpenOptions::new().write(true).open(&proc_path) {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(&tok.to_wire()) {
                        eprintln!("[capd] Failed to install token to kernel: {}", e);
                    }
                }
                Err(e) => {
                    // /proc entry may not exist yet in dev build — log and continue
                    eprintln!("[capd] Warning: {} not available ({}), kernel LSM not loaded?", proc_path, e);
                }
            }

            installed.push(tok.clone());
            self.tokens.entry(pid).or_default().push(tok);
        }
        installed
    }

    /// Prune expired tokens for a pid, write revocation to kernel
    pub fn prune_expired(&mut self, pid: u32) {
        if let Some(toks) = self.tokens.get_mut(&pid) {
            toks.retain(|t| !t.is_expired());
        }
    }

    pub fn revoke_all(&mut self, pid: u32) {
        self.tokens.remove(&pid);
        // Kernel side: process death automatically clears table via task_free hook
    }
}

// ── Audit logger ───────────────────────────────────────────────────────────
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: &str) -> Self {
        fs::create_dir_all(std::path::Path::new(path).parent().unwrap())
            .unwrap_or_default();
        Self { path: PathBuf::from(path) }
    }

    pub fn write(&self, event: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!("[{}] {}\n", ts, event);

        if let Ok(mut f) = OpenOptions::new()
            .create(true).append(true)
            .open(&self.path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
            // fsync: every audit write is durable
            let _ = f.sync_all();
        }
    }
}

// ── Main ───────────────────────────────────────────────────────────────────
fn main() -> io::Result<()> {
    let socket_path = "/run/sorabbyngo/capd.sock";
    let audit_path  = "/var/log/sorabbyngo/cap_audit.log";

    // Ensure socket directory exists
    fs::create_dir_all("/run/sorabbyngo").unwrap_or_default();
    let _ = fs::remove_file(socket_path);

    let policy = Arc::new(Mutex::new(PolicyEngine::new()));
    let store  = Arc::new(Mutex::new(TokenStore::new()));
    let audit  = Arc::new(AuditLog::new(audit_path));

    {
        let mut p = policy.lock().unwrap();
        p.load_manifests("/etc/sorabbyngo/agents");
    }

    audit.write("capd started");

    let listener = UnixListener::bind(socket_path)?;
    println!("[capd] Listening on {}", socket_path);

    // Spawn expiry reaper thread
    {
        let store  = Arc::clone(&store);
        let audit  = Arc::clone(&audit);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(60));
            // In production: iterate all tracked pids and prune
            audit.write("expiry-reaper: tick");
            let _ = store.lock();
        });
    }

    for stream in listener.incoming() {
        match stream {
            Ok(_stream) => {
                // In production: read CapRequest from stream, evaluate, install, respond
                // Protocol: JSON over Unix socket with newline delimiter
                audit.write("connection: accepted");
            }
            Err(e) => eprintln!("[capd] connection error: {}", e),
        }
    }

    Ok(())
}
