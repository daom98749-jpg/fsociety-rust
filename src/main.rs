//! fsociety-toolkit v1.0 (Rust edition)
//!
//! Basic network recon toolkit - runs on Windows, Linux, Termux (via proot/rust).
//! Only legitimate information-gathering features:
//!   - Public IP info
//!   - TCP port scanner + banner grabbing
//!   - HTTP inspector (status, headers, security headers check)
//!   - DNS lookup (A/AAAA) + reverse DNS (via system tools)
//!   - Ping / Traceroute (shells out to system ping/tracert/traceroute)
//!   - Domain WHOIS lookup (via public RDAP API)
//!   - System info
//!   - Export results to a JSON report
//!
//! No attack, exploitation, brute-force or DDoS functionality.

use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Mat khau "cong vao" gia lap, chi de hieu ung giao dien - khong phai co
/// che bao mat that su (so sanh chuoi don gian, luu ro rang trong source).
/// Doi gia tri nay neu muon dung mat khau khac.
const ACCESS_CODE: &str = "FSOCIETY";

const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017,
];

const R: &str = "\x1b[1;31m";
const G: &str = "\x1b[1;32m";
const Y: &str = "\x1b[1;33m";
const C: &str = "\x1b[1;36m";
const W: &str = "\x1b[1;37m";
const RST: &str = "\x1b[0m";

struct Report {
    entries: Mutex<Vec<Value>>,
}

impl Report {
    fn new() -> Self {
        Report {
            entries: Mutex::new(Vec::new()),
        }
    }

    fn log(&self, section: &str, data: Value) {
        let entry = json!({
            "section": section,
            "timestamp": now_iso(),
            "data": data,
        });
        self.entries.lock().unwrap().push(entry);
    }
}

fn now_iso() -> String {
    // No chrono dependency: use the system "date" command for a readable
    // local timestamp. Falls back to a fixed placeholder if unavailable.
    let fmt = if cfg!(windows) {
        Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Date -Format o"])
            .output()
    } else {
        Command::new("date").arg("-Iseconds").output()
    };
    match fmt {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn is_windows() -> bool {
    cfg!(windows)
}

fn clear_screen() {
    if is_windows() {
        let _ = Command::new("cmd").args(["/C", "cls"]).status();
    } else {
        let _ = Command::new("clear").status();
    }
}

fn pause() {
    print!("\n{C}Press Enter to return to the menu...{RST}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}

fn prompt(label: &str) -> String {
    print!("{W}{label}{RST}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

/// In ra mot chuoi log khoi dong gia lap (chi de tao hieu ung hinh anh,
/// khong co chuc nang thuc su dang sau). Chay 1 lan duy nhat luc mo chuong
/// trinh, truoc khi hien banner + menu chinh.
/// Man hinh nhap "ma truy cap" sau khi boot xong, truoc khi vao menu chinh.
/// Chi la hieu ung giao dien (so sanh chuoi don gian voi ACCESS_CODE),
/// khong phai lop bao mat that, va khong ma hoa/che giau ky tu go vao.
fn login_gate() {
    println!();
    println!("{R}==================================================={RST}");
    println!("{R}  RESTRICTED ACCESS - AUTHENTICATION REQUIRED{RST}");
    println!("{R}==================================================={RST}");

    loop {
        let input = prompt(&format!("\n{W}Enter access code: {RST}"));
        if input == ACCESS_CODE {
            println!("\n{G}[ACCESS GRANTED] Welcome back, operator.{RST}");
            std::thread::sleep(Duration::from_millis(700));
            break;
        } else {
            println!("{R}[ACCESS DENIED] Invalid code. Try again.{RST}");
        }
    }
}

fn boot_sequence() {
    clear_screen();

    let lines: &[(&str, &str)] = &[
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (Y, "[WAIT]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (Y, "[WAIT]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (Y, "[WAIT]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
        (G, "[ OK ]"),
    ];
    let messages = [
        "Initializing fsociety-toolkit core...",
        "Loading kernel compatibility shim...",
        "Mounting local module cache...",
        "Resolving dependency graph...",
        "Verifying binary checksums...",
        "Starting TCP/IP stack handlers...",
        "Loading network interface drivers...",
        "Enumerating local network adapters...",
        "Binding loopback interface...",
        "Loading DNS resolver tables...",
        "Caching root nameserver hints...",
        "Verifying RDAP/WHOIS endpoints...",
        "Negotiating RDAP schema version...",
        "Spinning up thread pool (scanner)...",
        "Allocating worker queues...",
        "Calibrating timeout thresholds...",
        "Loading common port signature table...",
        "Loading banner-grab signatures...",
        "Compiling service fingerprint rules...",
        "Loading HTTP header ruleset...",
        "Indexing security header checklist...",
        "Initializing HTTP client pool...",
        "Linking crypto primitives (tls)...",
        "Verifying trusted certificate store...",
        "Checking system permissions...",
        "Checking socket privilege level...",
        "Probing loopback latency...",
        "Loading ICMP helper routines...",
        "Preparing traceroute hop buffer...",
        "Preparing report serializer...",
        "Allocating JSON write buffer...",
        "Syncing internal clock source...",
        "Loading color/terminal capability table...",
        "Detecting terminal width...",
        "Priming output flush queue...",
        "Validating menu state machine...",
        "Registering event handlers...",
        "Finalizing module registry...",
        "Running self-diagnostics...",
        "Self-diagnostics passed.",
        "All systems nominal.",
    ];

    // Them mot loat dong log "mo-dun" sinh tu dong de boot log thanh "sieu
    // dai" ma khong phai go tay hang tram dong - chi de hieu ung, khong lam
    // gi that su.
    let module_kinds = [
        "net", "sys", "sec", "crypto", "fs", "sched", "io", "sock", "dns", "http",
    ];
    let mut all_messages: Vec<String> = messages.iter().map(|s| s.to_string()).collect();
    for i in 0..1957u32 {
        let kind = module_kinds[(i as usize) % module_kinds.len()];
        all_messages.push(format!(
            "Loading module {kind}_{:04x}.mod @ 0x{:06X}...",
            i,
            0x1000 + i * 0x40
        ));
    }
    all_messages.push("Finalizing module registry (pass 2)...".to_string());
    all_messages.push("All systems nominal.".to_string());

    println!("{C}==================================================={RST}");
    println!("{C}  fsociety-toolkit :: boot sequence{RST}");
    println!("{C}==================================================={RST}\n");

    for (i, msg) in all_messages.iter().enumerate() {
        let (color, tag) = lines[i % lines.len()];
        print!("  {color}{tag}{RST} {W}{msg}{RST}");
        let _ = io::stdout().flush();
        std::thread::sleep(Duration::from_millis(15));
        println!();
    }

    println!("\n{G}Boot complete. Launching menu...{RST}");
    std::thread::sleep(Duration::from_millis(1000));
}

fn banner() {
    clear_screen();
    println!(
        r#"{R}
  ███████╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗
  ██╔════╝██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
  █████╗  ███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝
  ██╔══╝  ╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝
  ██║     ███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║
  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝
{RST}{C}      [ network recon toolkit v1.0 (rust) | {} ]{RST}
"#,
        if is_windows() { "Windows" } else { "Unix/Termux" }
    );
}

// ----------------------------------------------------------------------
// 1. Public IP info
// ----------------------------------------------------------------------
fn public_ip_info(report: &Report) {
    println!("\n{G}[+] Fetching public IP info...{RST}");
    let result = ureq::get("https://ipinfo.io/json")
        .set("User-Agent", "fsociety-toolkit-rs/1.0")
        .timeout(Duration::from_secs(8))
        .call();

    match result {
        Ok(resp) => match resp.into_json::<Value>() {
            Ok(data) => {
                for key in ["ip", "hostname", "city", "region", "country", "org", "timezone"] {
                    if let Some(v) = data.get(key) {
                        let display = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                        println!("  {Y}{key:<10}{RST}: {W}{display}{RST}");
                    }
                }
                report.log("public_ip_info", data);
            }
            Err(e) => println!("{R}[!] Failed to parse response: {e}{RST}"),
        },
        Err(e) => println!("{R}[!] Could not fetch public IP info: {e}{RST}"),
    }
}

// ----------------------------------------------------------------------
// 2. Port scanner + banner grabbing
// ----------------------------------------------------------------------
fn scan_single_port(host: &str, port: u16, timeout: Duration) -> Option<(u16, &'static str)> {
    let addr_str = format!("{host}:{port}");
    let mut addrs = addr_str.to_socket_addrs().ok()?;
    let addr = addrs.next()?;
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some((port, well_known_service(port))),
        Err(_) => None,
    }
}

fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn grab_banner(host: &str, port: u16) -> String {
    let addr_str = format!("{host}:{port}");
    let Ok(mut addrs) = addr_str.to_socket_addrs() else {
        return String::new();
    };
    let Some(addr) = addrs.next() else {
        return String::new();
    };
    if port == 443 || port == 8443 {
        return "TLS/SSL service (banner not captured)".to_string();
    }
    match TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
            let mut buf = [0u8; 256];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().chars().take(120).collect(),
                _ => String::new(),
            }
        }
        Err(_) => String::new(),
    }
}

fn port_scanner(report: &Report) {
    let target = prompt("\nEnter target domain or IP: ");
    if target.is_empty() {
        println!("{R}[!] No target entered.{RST}");
        return;
    }

    let resolved_ip = match format!("{target}:0").to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(addr) => addr.ip().to_string(),
            None => {
                println!("{R}[!] Could not resolve target: {target}{RST}");
                return;
            }
        },
        Err(_) => {
            println!("{R}[!] Could not resolve target: {target}{RST}");
            return;
        }
    };

    println!("{C}[*] Target: {target} ({resolved_ip}){RST}");
    println!("{Y}1.{RST} Quick scan of common ports ({} ports)", COMMON_PORTS.len());
    println!("{Y}2.{RST} Custom port range (e.g. 1-1024)");
    let mode = prompt("Choose mode [1/2]: ");

    let ports: Vec<u16> = if mode == "2" {
        let rng = prompt("Enter port range (start-end): ");
        let parts: Vec<&str> = rng.splitn(2, '-').collect();
        if parts.len() != 2 {
            println!("{R}[!] Invalid port range.{RST}");
            return;
        }
        let start: u32 = match parts[0].trim().parse() {
            Ok(v) => v,
            Err(_) => {
                println!("{R}[!] Invalid port range.{RST}");
                return;
            }
        };
        let mut end: u32 = match parts[1].trim().parse() {
            Ok(v) => v,
            Err(_) => {
                println!("{R}[!] Invalid port range.{RST}");
                return;
            }
        };
        if start < 1 || end > 65535 || start > end {
            println!("{R}[!] Invalid port range.{RST}");
            return;
        }
        if end - start > 5000 {
            println!("{Y}[!] Range too large, limiting to the first 5000 ports.{RST}");
            end = start + 4999;
        }
        (start..=end).map(|p| p as u16).collect()
    } else {
        COMMON_PORTS.to_vec()
    };

    let do_banner = prompt("Attempt banner grabbing on open ports? (y/N): ").to_lowercase() == "y";

    println!("\n{G}[+] Scanning {} TCP ports...{RST}", ports.len());
    let start_time = Instant::now();
    let timeout = Duration::from_millis(1000);

    let resolved_ip_ref = &resolved_ip;
    let open_ports: Mutex<Vec<(u16, &'static str)>> = Mutex::new(Vec::new());
    let open_ports_ref = &open_ports;

    std::thread::scope(|s| {
        // Chunk the port list to cap concurrent threads at a reasonable number.
        for chunk in ports.chunks(80) {
            s.spawn(move || {
                for &port in chunk {
                    if let Some(result) = scan_single_port(resolved_ip_ref, port, timeout) {
                        open_ports_ref.lock().unwrap().push(result);
                    }
                }
            });
        }
    });

    let mut open_ports = open_ports.into_inner().unwrap();
    open_ports.sort_by_key(|(p, _)| *p);
    let elapsed = start_time.elapsed().as_secs_f64();

    let mut results = Vec::new();
    if open_ports.is_empty() {
        println!("\n{Y}[-] No open ports found in the scanned range ({elapsed:.2}s).{RST}");
    } else {
        println!("\n{G}[OK] Open ports ({elapsed:.2}s):{RST}");
        for (port, svc) in &open_ports {
            let banner_text = if do_banner {
                grab_banner(resolved_ip_ref, *port)
            } else {
                String::new()
            };
            let mut line = format!("  {C}Port {port:<5}{RST} -> {G}OPEN{RST} ({svc})");
            if !banner_text.is_empty() {
                line += &format!("  {Y}| banner:{RST} {banner_text}");
            }
            println!("{line}");
            results.push(json!({"port": *port, "service": *svc, "banner": banner_text}));
        }
    }

    report.log(
        "port_scan",
        json!({
            "target": target,
            "resolved_ip": resolved_ip,
            "ports_scanned": ports.len(),
            "open_ports": results,
            "elapsed_seconds": elapsed,
        }),
    );
}

// ----------------------------------------------------------------------
// 3. HTTP inspector + security headers check
// ----------------------------------------------------------------------
const SECURITY_HEADERS: &[&str] = &[
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
];

fn http_inspector(report: &Report) {
    let mut url = prompt("\nEnter URL (e.g. https://example.com): ");
    if url.is_empty() {
        return;
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("https://{url}");
    }

    println!("\n{G}[+] Checking {url}...{RST}");

    let mut headers_map: Vec<(String, String)> = Vec::new();
    let mut status_line = String::new();
    let mut final_url = url.clone();

    let request = ureq::request("HEAD", &url)
        .set("User-Agent", "Mozilla/5.0 (fsociety-toolkit-rs)")
        .timeout(Duration::from_secs(10));

    match request.call() {
        Ok(resp) => {
            status_line = format!("{} {}", resp.status(), resp.status_text());
            final_url = resp.get_url().to_string();
            for name in resp.headers_names() {
                if let Some(value) = resp.header(&name) {
                    headers_map.push((name.clone(), value.to_string()));
                }
            }
            println!("  {Y}Status     :{RST} {G}{status_line}{RST}");
            println!("  {Y}Final URL  :{RST} {final_url}");
            for (k, v) in &headers_map {
                println!("  {C}{k:<28}{RST}: {v}");
            }
        }
        Err(ureq::Error::Status(code, resp)) => {
            status_line = format!("{code} {}", resp.status_text());
            println!("  {Y}HTTP Error :{RST} {R}{status_line}{RST}");
            for name in resp.headers_names() {
                if let Some(value) = resp.header(&name) {
                    headers_map.push((name.clone(), value.to_string()));
                    println!("  {C}{name:<28}{RST}: {value}");
                }
            }
        }
        Err(e) => {
            println!("{R}[!] Connection error: {e}{RST}");
            return;
        }
    }

    println!("\n{G}[+] Security headers check:{RST}");
    let mut missing = Vec::new();
    for h in SECURITY_HEADERS {
        let present = headers_map.iter().any(|(k, _)| k.eq_ignore_ascii_case(h));
        if present {
            println!("  {G}[v]{RST} {h}");
        } else {
            println!("  {R}[x]{RST} {h} {Y}(missing){RST}");
            missing.push(h.to_string());
        }
    }

    let headers_json: Value = headers_map
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect::<serde_json::Map<String, Value>>()
        .into();

    report.log(
        "http_inspector",
        json!({
            "url": final_url,
            "status": status_line,
            "headers": headers_json,
            "missing_security_headers": missing,
        }),
    );
}

// ----------------------------------------------------------------------
// 4. DNS lookup + reverse DNS
// ----------------------------------------------------------------------
fn dns_lookup(report: &Report) {
    let host = prompt("\nEnter domain to look up: ");
    if host.is_empty() {
        return;
    }
    println!("\n{G}[+] Address records for {host}:{RST}");

    let mut records = Vec::new();
    match format!("{host}:0").to_socket_addrs() {
        Ok(addrs) => {
            let mut seen = std::collections::HashSet::new();
            for addr in addrs {
                let ip = addr.ip().to_string();
                let family = if addr.is_ipv6() { "IPv6" } else { "IPv4" };
                if seen.insert((family, ip.clone())) {
                    println!("  {Y}{family:<6}{RST}: {W}{ip}{RST}");
                    records.push(json!({"type": family, "ip": ip}));
                }
            }
        }
        Err(e) => {
            println!("{R}[!] No DNS records found: {e}{RST}");
            return;
        }
    }

    if records.is_empty() {
        println!("{Y}[-] No address records found.{RST}");
        return;
    }

    let do_reverse = prompt("\nReverse-lookup the first IP? (y/N): ").to_lowercase() == "y";
    let mut reverse = Value::Null;
    if do_reverse {
        if let Some(ip) = records[0].get("ip").and_then(|v| v.as_str()) {
            // No reverse-DNS in std; shell out to nslookup, available on
            // Windows, Linux and Termux (via `pkg install dnsutils` if missing).
            let output = Command::new("nslookup").arg(ip).output();
            match output {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    println!("  {C}Reverse DNS raw output:{RST}");
                    for line in text.lines() {
                        if line.to_lowercase().contains("name") {
                            println!("    {W}{line}{RST}");
                        }
                    }
                    reverse = json!(text.to_string());
                }
                Err(e) => println!("{R}[!] Could not run nslookup: {e}{RST}"),
            }
        }
    }

    report.log("dns_lookup", json!({"host": host, "records": records, "reverse": reverse}));
}

// ----------------------------------------------------------------------
// 5 & 6. Ping / Traceroute (delegates to the OS tools, like the original)
// ----------------------------------------------------------------------
fn ping_host() {
    let target = prompt("\nEnter host to ping: ");
    if target.is_empty() {
        return;
    }
    println!("\n{G}[+] Pinging {target}...{RST}\n");
    let count_flag = if is_windows() { "-n" } else { "-c" };
    let status = Command::new("ping").args([count_flag, "4", &target]).status();
    if status.is_err() {
        println!("{R}[!] Could not find the 'ping' command on this system.{RST}");
    }
}

fn traceroute_host() {
    let target = prompt("\nEnter host to traceroute: ");
    if target.is_empty() {
        return;
    }
    println!("\n{G}[+] Tracing route to {target} (this can take a while)...{RST}\n");
    let cmd = if is_windows() { "tracert" } else { "traceroute" };
    let status = Command::new(cmd).arg(&target).status();
    if status.is_err() {
        println!("{R}[!] Could not find the '{cmd}' command on this system.{RST}");
    }
}

// ----------------------------------------------------------------------
// 7. WHOIS lookup via public RDAP API
// ----------------------------------------------------------------------
fn whois_lookup(report: &Report) {
    let domain = prompt("\nEnter domain to look up: ");
    if domain.is_empty() {
        return;
    }
    println!("\n{G}[+] Looking up WHOIS/RDAP for {domain}...{RST}");

    let url = format!("https://rdap.org/domain/{domain}");
    match ureq::get(&url).timeout(Duration::from_secs(10)).call() {
        Ok(resp) => match resp.into_json::<Value>() {
            Ok(data) => {
                let name = data
                    .get("ldhName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&domain);
                println!("  {Y}Domain      {RST}: {name}");

                if let Some(events) = data.get("events").and_then(|v| v.as_array()) {
                    for ev in events {
                        let action = ev.get("eventAction").and_then(|v| v.as_str()).unwrap_or("");
                        let date = ev.get("eventDate").and_then(|v| v.as_str()).unwrap_or("");
                        println!("  {Y}{action:<12}{RST}: {date}");
                    }
                }
                if let Some(ns) = data.get("nameservers").and_then(|v| v.as_array()) {
                    let names: Vec<String> = ns
                        .iter()
                        .filter_map(|n| n.get("ldhName").and_then(|v| v.as_str()).map(String::from))
                        .collect();
                    if !names.is_empty() {
                        println!("  {Y}Nameservers {RST}: {}", names.join(", "));
                    }
                }
                if let Some(status) = data.get("status").and_then(|v| v.as_array()) {
                    let statuses: Vec<String> = status
                        .iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect();
                    if !statuses.is_empty() {
                        println!("  {Y}Status      {RST}: {}", statuses.join(", "));
                    }
                }
                report.log("whois", json!({"domain": domain, "raw": data}));
            }
            Err(e) => println!("{R}[!] Failed to parse RDAP response: {e}{RST}"),
        },
        Err(e) => println!("{R}[!] WHOIS lookup failed (domain may not support RDAP): {e}{RST}"),
    }
}

// ----------------------------------------------------------------------
// 8. System info
// ----------------------------------------------------------------------
fn sys_info() {
    println!("\n{G}[+] System info:{RST}");
    println!("  {Y}OS          {RST}: {}", std::env::consts::OS);
    println!("  {Y}Architecture{RST}: {}", std::env::consts::ARCH);

    let hostname_cmd = if is_windows() { "hostname" } else { "hostname" };
    if let Ok(out) = Command::new(hostname_cmd).output() {
        let name = String::from_utf8_lossy(&out.stdout);
        println!("  {Y}Hostname    {RST}: {}", name.trim());
    }
}

// ----------------------------------------------------------------------
// 9. Export report
// ----------------------------------------------------------------------
fn export_report(report: &Report) {
    let entries = report.entries.lock().unwrap();
    if entries.is_empty() {
        println!("{Y}[!] No data to export yet. Run a few features first.{RST}");
        return;
    }

    let generated_at = now_iso();
    let full_report = json!({
        "generated_at": generated_at,
        "entries": entries.clone(),
    });

    let default_name = format!(
        "fsociety_report_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let name = prompt(&format!("\nOutput filename (Enter to use '{default_name}'): "));
    let name = if name.is_empty() { default_name } else { name };

    match std::fs::File::create(&name) {
        Ok(file) => {
            if serde_json::to_writer_pretty(file, &full_report).is_ok() {
                match std::fs::canonicalize(&name) {
                    Ok(path) => println!("{G}[OK] Report saved to: {}{RST}", path.display()),
                    Err(_) => println!("{G}[OK] Report saved to: {name}{RST}"),
                }
            } else {
                println!("{R}[!] Failed to write JSON report.{RST}");
            }
        }
        Err(e) => println!("{R}[!] Could not create file: {e}{RST}"),
    }
}

// ----------------------------------------------------------------------
// Main menu
// ----------------------------------------------------------------------
fn main() {
    let report = Report::new();

    boot_sequence();
    login_gate();

    loop {
        banner();
        println!("  {Y}[1]{RST} Public IP & network info");
        println!("  {Y}[2]{RST} TCP port scan + banner grabbing");
        println!("  {Y}[3]{RST} HTTP status/headers + security headers check");
        println!("  {Y}[4]{RST} DNS lookup (A/AAAA) + reverse DNS");
        println!("  {Y}[5]{RST} Ping host");
        println!("  {Y}[6]{RST} Traceroute to host");
        println!("  {Y}[7]{RST} Domain WHOIS lookup");
        println!("  {Y}[8]{RST} System info");
        println!("  {Y}[9]{RST} Export JSON report from results so far");
        println!("  {R}[0]{RST} Exit\n");

        let choice = prompt(&format!("{C}fsociety{RST}:{W}~{RST}$ "));
        match choice.as_str() {
            "0" => {
                println!("\n{R}Good luck.{RST}");
                break;
            }
            "1" => {
                public_ip_info(&report);
                pause();
            }
            "2" => {
                port_scanner(&report);
                pause();
            }
            "3" => {
                http_inspector(&report);
                pause();
            }
            "4" => {
                dns_lookup(&report);
                pause();
            }
            "5" => {
                ping_host();
                pause();
            }
            "6" => {
                traceroute_host();
                pause();
            }
            "7" => {
                whois_lookup(&report);
                pause();
            }
            "8" => {
                sys_info();
                pause();
            }
            "9" => {
                export_report(&report);
                pause();
            }
            _ => {
                println!("{R}[!] Invalid choice.{RST}");
                std::thread::sleep(Duration::from_millis(800));
            }
        }
    }
}
