# Fsociety Toolkit (Rust edition)

A basic network recon toolkit written in Rust. Runs on Windows, Linux, and Termux (Android).

Includes only legitimate information-gathering functions — no attack, exploitation, or password-cracking capabilities.

## Features

- Public IP lookup
- TCP port scanner + banner grabbing
- HTTP status / headers check + security headers audit
- DNS lookup (A/AAAA) + reverse DNS
- Ping / Traceroute
- Domain WHOIS lookup (via public RDAP API)
- System info
- Export scan results to a JSON report
- Boot-sequence intro screen + simple access-code gate (cosmetic only)

## Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs))
- Internet access on first build (to fetch the `ureq` and `serde_json` crates)

## Install

Install directly from this repo with cargo:

```bash
cargo install --git https://github.com/daom98749-jpg/fsociety-rust --force
```

This builds the binary and places it in `~/.cargo/bin` (already on your PATH after installing Rust), so you can run it from anywhere:

```bash
fsociety-toolkit
```

## Build from source

```bash
git clone https://github.com/daom98749-jpg/fsociety-rust.git
cd fsociety-rust
cargo run --release
```

## Usage

After the boot sequence and access-code prompt (default code: `FSOCIETY`), a menu appears:

```
  [1] Public IP & network info
  [2] TCP port scan + banner grabbing
  [3] HTTP status/headers + security headers check
  [4] DNS lookup (A/AAAA) + reverse DNS
  [5] Ping host
  [6] Traceroute to host
  [7] Domain WHOIS lookup
  [8] System info
  [9] Export JSON report from results so far
  [0] Exit
```

## License

MIT — for educational and legitimate network-testing purposes only, on systems you own or are authorized to test.
