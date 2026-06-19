<div align="center">

# 🔍 ReconX-Pro

### Elite Reconnaissance Framework

**A professional-grade, modular reconnaissance toolkit for bug bounty hunters & penetration testers.**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-2.0.0-blueviolet.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen.svg)

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Usage](#-usage) • [Output](#-output) • [Architecture](#-architecture)

</div>

---

## 📖 Overview

**ReconX-Pro** is an all-in-one reconnaissance framework that orchestrates passive and active
information-gathering across a target domain and consolidates everything into a single, clean
report. It blends native Python modules with battle-tested external tools (subfinder, httpx,
naabu, nmap, ffuf, gowitness, and more) and enriches results with premium data sources
(Shodan, Censys, VirusTotal, SecurityTrails, Chaos, BuiltWith, GitHub).

Built around a **modular, plug-and-play architecture** — every check is an independent module,
so you can enable, disable, or extend capabilities from a single config file.

> ⚠️ **Legal Notice** — ReconX-Pro is intended **only** for authorized security testing,
> bug bounty engagements, and educational use. Always obtain **explicit written permission**
> before scanning any target. You are solely responsible for your actions.

---

## 🎬 Demo

<video src="https://github.com/3bwahab/ReconX-Pro/raw/main/ReconX_pro.mp4" controls muted loop width="100%"></video>

<a href="https://github.com/3bwahab/ReconX-Pro/raw/main/ReconX_pro.mp4">▶️ Watch the demo</a> if the player above doesn't load.

---

## ⚡ Features

### 🔍 Passive Reconnaissance

| Module                       | Description                                                                                  |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| **WHOIS Lookup**             | Domain registration, registrar & ownership details                                           |
| **DNS Enumeration**          | Full DNS record discovery (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, DMARC)                 |
| **Subdomain Enumeration**    | Multi-source discovery (subfinder, crt.sh, HackerTarget, ThreatCrowd, BufferOver)            |
| **Certificate Transparency** | SSL certificate analysis & CT log querying                                                   |
| **Shodan Intelligence**      | Host, service & CVE intelligence via the Shodan API                                          |
| **Censys Intelligence**      | Certificate & host data via the Censys API                                                   |
| **VirusTotal**               | Domain reputation & threat intelligence                                                      |
| **SecurityTrails**           | Historical DNS & subdomain intelligence                                                      |
| **Chaos (ProjectDiscovery)** | Curated public bug-bounty subdomain dataset                                                  |
| **GitHub Recon**             | Leaked secrets, sensitive files & code references                                            |
| **BuiltWith**                | Technology stack profiling                                                                   |
| **Wayback URLs**             | Historical URL discovery (waybackurls, gau, CDX API)                                         |
| **ASN Intelligence**         | IP intelligence, geolocation & ASN data                                                      |

### ⚔️ Active Reconnaissance

| Module                    | Description                                                  |
| ------------------------- | ------------------------------------------------------------ |
| **Live Host Detection**   | HTTP probing via httpx with technology detection             |
| **Port Scanning**         | Open-port discovery via naabu/nmap with service detection    |
| **Directory Fuzzing**     | Hidden directory & file discovery via ffuf                   |
| **HTTP Headers Analysis** | Security-header audit with vulnerability flagging            |
| **Technology Detection**  | CMS, framework & server fingerprinting                       |
| **Screenshot Capture**    | Visual reconnaissance via gowitness                          |

### 🛡️ Security Analysis

- Missing security-header detection
- SPF / DMARC / DNSSEC validation
- Cookie security audit
- Information-disclosure detection
- Zone-transfer testing
- CVE correlation (via Shodan)

### 📊 Reporting

- Interactive, self-contained **HTML report**
- Machine-readable **JSON report** for pipelines & tooling
- Consolidated artifact files (`all_subdomains.txt`, `alive_urls.txt`, …)
- Rich, colorized terminal output

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- *(Optional)* **Go 1.20+** for the external Go-based tools
- *(Optional)* `nmap` for service/version detection

### 1. Clone & install Python dependencies

```bash
git clone https://github.com/3bwahab/ReconX-Pro.git
cd ReconX-Pro

# (recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 2. (Optional) Install external tools for full capability

```bash
# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/sensepost/gowitness@latest

# System tools
sudo apt install nmap          # Debian / Ubuntu
```

> ReconX-Pro degrades gracefully — any tool or API key that isn't configured is simply skipped.

---

## 🔐 Configuration

API keys are read from a local **`config.yaml`** file. This file is **git-ignored** so your
secrets are never committed.

```bash
# Create your local config from the template
cp config.example.yaml config.yaml

# then edit config.yaml and paste your API keys
```

### Environment variable overrides

Any key can be supplied (or overridden) via environment variables — ideal for CI and shared machines:

| Environment Variable      | Config Key                |
| ------------------------- | ------------------------- |
| `SHODAN_API_KEY`          | `api_keys.shodan`         |
| `CENSYS_API_TOKEN`        | `api_keys.censys_token`   |
| `VIRUSTOTAL_API_KEY`      | `api_keys.virustotal`     |
| `SECURITYTRAILS_API_KEY`  | `api_keys.securitytrails` |
| `CHAOS_API_KEY`           | `api_keys.chaos`          |
| `GITHUB_TOKEN`            | `api_keys.github_token`   |
| `BUILTWITH_API_KEY`       | `api_keys.builtwith`      |

```bash
export SHODAN_API_KEY="your_key_here"
export GITHUB_TOKEN="your_token_here"
```

### Where to get API keys

| Service        | Sign-up                                            |
| -------------- | -------------------------------------------------- |
| Shodan         | https://account.shodan.io/                         |
| Censys         | https://search.censys.io/account/api               |
| VirusTotal     | https://www.virustotal.com/gui/my-apikey           |
| SecurityTrails | https://securitytrails.com/app/account             |
| Chaos          | https://chaos.projectdiscovery.io/                 |
| GitHub         | https://github.com/settings/tokens                 |
| BuiltWith      | https://api.builtwith.com/                         |

---

## 🚀 Usage

### Interactive mode

```bash
python main.py
```

You'll see the API-key status table and a menu to choose your reconnaissance mode.

### Command-line (non-interactive) mode

```bash
# Passive recon
python main.py -d example.com -m 1

# Active recon
python main.py -d example.com -m 2

# Full recon (passive + active)
python main.py -d example.com -m 3
```

### Options

| Flag                | Description                                       |
| ------------------- | ------------------------------------------------- |
| `-d`, `--domain`    | Target domain (e.g. `example.com`)                |
| `-m`, `--mode`      | Recon mode: `1`=Passive, `2`=Active, `3`=Full     |
| `-c`, `--config`    | Path to config file (default: `config.yaml`)      |
| `-o`, `--output`    | Output directory (default: `reports/`)            |
| `-t`, `--threads`   | Number of concurrent threads (default: `10`)      |
| `--json-only`       | Generate only the JSON report (skip HTML)         |
| `--passive-only`    | Alias for `-m 1`                                  |
| `--active-only`     | Alias for `-m 2`                                  |

---

## 📂 Output

Each run produces a timestamped directory under `reports/`:

```
reports/
└── example.com_2026-06-19_14-30-00/
    ├── report.html          # Interactive visual report
    ├── report.json          # Structured machine-readable data
    ├── all_subdomains.txt    # Every subdomain discovered
    ├── alive_subdomains.txt  # Resolving / live subdomains
    ├── all_urls.txt          # Every URL discovered
    └── alive_urls.txt        # Live URLs
```

---

## 🏗️ Architecture

```
ReconX-Pro/
├── main.py                 # CLI entry point & interactive menu
├── config.example.yaml     # Configuration template (copy to config.yaml)
├── requirements.txt
├── setup.py
│
├── core/                   # Framework engine
│   ├── config.py           # Config loading + env-var overrides
│   ├── runner.py           # Orchestrates module execution
│   ├── base_module.py      # Base class every module inherits
│   ├── post_processor.py   # Result aggregation & de-duplication
│   └── report_engine.py    # HTML / JSON report generation
│
├── modules/                # Reconnaissance modules
│   ├── passive/            # WHOIS, DNS, subdomains, CT, wayback, ASN...
│   └── active/             # Live hosts, ports, fuzzing, headers, tech, screenshots
│
├── integrations/           # External API & tool wrappers
│   ├── shodan_api.py        censys_api.py        virustotal_api.py
│   ├── securitytrails_api.py chaos_api.py         builtwith_api.py
│   ├── github_recon.py       subfinder.py         httpx_runner.py
│   ├── naabu.py              nmap_runner.py        ffuf_runner.py
│   └── waybackurls.py        gau_runner.py
│
├── utils/                  # Logging & helpers
├── templates/              # HTML report templates
└── reports/                # Generated output (git-ignored)
```

### Extending ReconX-Pro

Each module subclasses `core.base_module.BaseModule`, so adding a new capability is as simple as:

1. Create a new module in `modules/passive/` or `modules/active/`.
2. Implement the `run()` method returning structured results.
3. Register it in `config.yaml` under the relevant `modules:` section.

---

## 🛠️ Tech Stack

- **Python 3.8+** — core framework
- **rich** — beautiful terminal UI
- **requests / urllib3** — HTTP & API clients
- **dnspython** — DNS resolution
- **python-whois** — WHOIS lookups
- **pyyaml** — configuration

---

## 🤝 Contributing

Contributions are welcome! Fork the repo, create a feature branch, and open a pull request.
For major changes, please open an issue first to discuss what you'd like to change.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for details.

---

## 👤 Author

**3bwahab**
GitHub: [@3bwahab](https://github.com/3bwahab)

---

<div align="center">

⭐ **If ReconX-Pro helps you, consider giving it a star!** ⭐

*Use responsibly. Hack ethically.*

</div>
