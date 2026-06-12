//! domain-mode — Sorabbyngo domain mode manager
use std::fs;
use std::io::Write;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub enum DomainMode { Security, Ai, Dev, Gaming }

impl DomainMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "security" => Some(DomainMode::Security),
            "ai"       => Some(DomainMode::Ai),
            "dev"      => Some(DomainMode::Dev),
            "gaming"   => Some(DomainMode::Gaming),
            _          => None,
        }
    }

    pub fn sched_profile(&self) -> u8 {
        match self {
            DomainMode::Security => 1,
            DomainMode::Ai       => 2,
            DomainMode::Dev      => 0,
            DomainMode::Gaming   => 1,
        }
    }

    pub fn services_start(&self) -> &[&str] {
        match self {
            DomainMode::Security => &["tor", "sorabbyngo-audit-collector"],
            DomainMode::Ai       => &["sorabbyngo-inference-daemon", "byngox"],
            DomainMode::Dev      => &["docker", "sorabbyngo-toolbox"],
            DomainMode::Gaming   => &["gamemode"],
        }
    }

    pub fn services_stop(&self) -> &[&str] {
        match self {
            DomainMode::Security => &["sorabbyngo-inference-daemon", "gamemode"],
            DomainMode::Ai       => &["tor", "gamemode"],
            DomainMode::Dev      => &["tor", "gamemode"],
            DomainMode::Gaming   => &["tor", "sorabbyngo-inference-daemon"],
        }
    }

    pub fn name(&self) -> &str {
        match self {
            DomainMode::Security => "security",
            DomainMode::Ai       => "ai",
            DomainMode::Dev      => "dev",
            DomainMode::Gaming   => "gaming",
        }
    }

    pub fn gpu_mode(&self) -> &str {
        match self {
            DomainMode::Gaming   => "exclusive",
            DomainMode::Ai       => "compute",
            DomainMode::Dev      => "shared",
            DomainMode::Security => "restricted",
        }
    }
}

fn audit(msg: &str) {
    let ts   = SystemTime::now().duration_since(UNIX_EPOCH)
                   .unwrap_or_default().as_secs();
    let line = format!("[{}] {}\n", ts, msg);
    let _    = fs::OpenOptions::new()
        .create(true).append(true)
        .open("/var/log/sorabbyngo/domain_mode.log")
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

fn set_sched_profile(profile: u8) {
    let path = "/sys/kernel/sorabbyngo/sched_profile";
    match fs::write(path, profile.to_string()) {
        Ok(_)  => println!("[domain-mode] sched_profile={}", profile),
        Err(e) => eprintln!("[domain-mode] sched_profile unavailable (kernel patch not loaded): {}", e),
    }
}

fn notify_capd(mode: &str) {
    // Write to capd socket when protocol is implemented
    println!("[domain-mode] -> capd: mode={}", mode);
}

fn run_service(action: &str, svc: &str) {
    let out = Command::new("systemctl").args([action, svc]).output();
    match out {
        Ok(o) if o.status.success() => println!("[domain-mode] {} {}", action, svc),
        _ => eprintln!("[domain-mode] systemctl {} {} (not found or failed)", action, svc),
    }
}

fn switch_to(mode: &DomainMode) {
    println!("[domain-mode] Switching -> {}", mode.name());

    set_sched_profile(mode.sched_profile());
    notify_capd(mode.name());

    for svc in mode.services_stop()  { run_service("stop",  svc); }
    for svc in mode.services_start() { run_service("start", svc); }

    println!("[domain-mode] gpu_mode={}", mode.gpu_mode());
    println!("[domain-mode] -> wayland-shell: mode={}", mode.name());

    audit(&format!("domain-mode-switch mode={}", mode.name()));
    println!("[domain-mode] Done — mode={}", mode.name());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: domain-mode <security|ai|dev|gaming>");
        std::process::exit(1);
    }

    match DomainMode::from_str(&args[1]) {
        Some(mode) => switch_to(&mode),
        None => {
            eprintln!("Unknown mode: {}. Use: security | ai | dev | gaming", args[1]);
            std::process::exit(1);
        }
    }
}
