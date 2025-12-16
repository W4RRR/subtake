<p align="center">
  <img src="assets/logo.png" alt="SubTake Flow Logo" width="400">
</p>

<h1 align="center">🔥 SubTake Flow</h1>

<p align="center">
  <em>by .W4R</em>
</p>

<p align="center">
  <strong>Advanced Subdomain Takeover Scanner with Intelligent Heuristics</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/bash-5.0+-green?style=flat-square" alt="Bash">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

```
   _____       __  ______      __
  / ___/__  __/ /_/_  __/___ _/ /_____
  \__ \/ / / / __ \/ / / __ `/ //_/ _ \
 ___/ / /_/ / /_/ / / / /_/ / ,< /  __/
/____/\__,_/_.___/_/  \__,_/_/|_|\___/
   ________
  / ____/ /___ _      __
 / /_  / / __ \ | /| / /
/ __/ / / /_/ / |/ |/ /
/_/   /_/\____/|__/|__/
                        by .W4R
```

## 🎯 What is SubTake Flow?

SubTake Flow is a **professional-grade subdomain takeover detection tool** designed for Red Team operations and bug bounty hunting. Unlike simple wrapper scripts, it implements intelligent heuristics to minimize false positives while maximizing detection rates.

### The Problem with Existing Tools

Most subdomain takeover tools suffer from:
- **High false positive rates** - Wasting hours investigating non-issues
- **Missing edge cases** - Not detecting subtle takeover opportunities  
- **Single-point verification** - Trusting one tool's output blindly

### Our Solution

SubTake Flow combines **multiple verification layers**:
1. 🔍 **Comprehensive enumeration** using subfinder & amass
2. 🧬 **CNAME chain analysis** to identify dangling records
3. 🤖 **Automated scanning** with subzy for initial detection
4. 🎯 **Deep verification** with intelligent scoring algorithm
5. 📊 **Beautiful reports** in HTML, JSON, and TSV formats

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🎨 **Beautiful CLI** | Color-coded output with progress bars and ASCII art |
| 🔥 **Smart Scoring** | Probability-based vulnerability detection (0-100%) |
| 🌐 **150+ Fingerprints** | Extensive database of cloud service signatures |
| ⚡ **Parallel Processing** | GNU Parallel support for faster scanning |
| 🛡️ **Wildcard Detection** | Automatic wildcard DNS detection to avoid false positives |
| 📋 **Multiple Outputs** | HTML report, JSON, and TSV for automation |
| 🔧 **Highly Configurable** | Custom resolvers, timeouts, threads, and wordlists |
| 🧩 **Modular Design** | External fingerprints file for easy updates |

---

## 📦 Installation

### Prerequisites

**Required:**
```bash
# Debian/Ubuntu
sudo apt install dnsutils curl jq openssl

# macOS (with Homebrew)
brew install bind curl jq openssl
```

**Optional (Enhanced Features):**
```bash
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/PentestPad/subzy@latest

# GNU Parallel for faster scanning
sudo apt install parallel  # Debian/Ubuntu
brew install parallel      # macOS
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/W4RRR/subtake.git
cd subtake

# Make executable
chmod +x subtake.sh

# (Optional) Add to PATH
sudo ln -s $(pwd)/subtake.sh /usr/local/bin/subtake
```

### Verify Installation

```bash
./subtake.sh --version
./subtake.sh --help
```

---

## 🚀 Usage

### Basic Scan

```bash
./subtake.sh example.com
```

### Advanced Options

```bash
# Full scan with custom settings
./subtake.sh -o ./results -j 20 -t 15 example.com

# Use existing subdomain list
./subtake.sh -s subdomains.txt --skip-enum example.com

# With custom wordlist for bruteforce
./subtake.sh -w /path/to/wordlist.txt example.com

# Custom DNS resolvers
./subtake.sh -r "1.1.1.1,8.8.8.8,9.9.9.9" example.com

# Debug mode
./subtake.sh --debug example.com
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <dir>` | Output directory | `./subtake_<domain>` |
| `-t, --timeout <sec>` | HTTP timeout | `10` |
| `-j, --threads <num>` | Parallel threads | `10` |
| `-r, --resolvers <list>` | DNS resolvers (comma-separated) | `1.1.1.1,8.8.8.8,9.9.9.9` |
| `-w, --wordlist <file>` | Custom wordlist | - |
| `-s, --subdomains <file>` | Use existing subdomain list | - |
| `-f, --fingerprints <file>` | Custom fingerprints YAML | `fingerprints.yaml` |
| `--skip-enum` | Skip subdomain enumeration | - |
| `--skip-subzy` | Skip automated subzy scan | - |
| `--debug` | Enable debug output | - |

---

## 🔬 How It Works

### Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SubTake Flow Pipeline                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Step 0     │    │   Step 1     │    │   Step 2     │              │
│  │   Wildcard   │───▶│  Subdomain   │───▶│     DNS      │              │
│  │  Detection   │    │ Enumeration  │    │  Resolution  │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│                                                  │                      │
│                                                  ▼                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Step 5     │    │   Step 4     │    │   Step 3     │              │
│  │   Report     │◀───│    Deep      │◀───│  Automated   │              │
│  │ Generation   │    │ Verification │    │    Scan      │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Probability Scoring Algorithm

The tool calculates a **vulnerability probability score (0-100%)** based on:

| Factor | Points | Description |
|--------|--------|-------------|
| Known Provider | +30 | CNAME points to known vulnerable service |
| NXDOMAIN Target | +35 | CNAME target doesn't resolve |
| HTTP 404 | +15 | Target returns Not Found |
| HTTP 502/503 | +20 | Backend service error |
| Fingerprint Match | +40 | Error page matches known signature |

**Classification:**
- 🔴 **VULNERABLE** (70-100%): Confirmed takeover opportunity
- 🟡 **HIGH** (40-69%): Strong candidate, manual review recommended
- 🔵 **MEDIUM** (20-39%): Possible issue, investigate further
- ⚪ **LOW** (0-19%): Unlikely to be vulnerable

---

## 📊 Output Files

After a scan, you'll find these files in the output directory:

```
subtake_example.com/
├── subdomains.txt      # Discovered subdomains
├── dns_resolved.tsv    # DNS resolution with CNAMEs
├── subzy_results.txt   # Automated scan results
├── results.tsv         # Final verification results
├── results.json        # JSON format for automation
├── report.html         # Interactive HTML report
└── scan.log            # Detailed execution log
```

### HTML Report Preview

The HTML report features:
- 📈 Statistics dashboard
- 🔍 Sortable results table
- 🎨 Color-coded severity levels
- 📱 Responsive design

---

## 🧩 Fingerprints Database

The `fingerprints.yaml` file contains **150+ signatures** for vulnerable cloud services:

- **AWS**: S3, CloudFront, Elastic Beanstalk, ELB
- **Azure**: Web Apps, Blob Storage, CDN, Traffic Manager
- **Google Cloud**: Cloud Storage, App Engine
- **Platforms**: GitHub Pages, Heroku, Netlify, Vercel
- **SaaS**: Shopify, Zendesk, HubSpot, Ghost, Tumblr
- **And many more...**

### Adding Custom Fingerprints

Edit `fingerprints.yaml`:

```yaml
- cname: "custom-service.com"
  provider: "Custom Service"
  fingerprint: "Error message pattern|Another pattern"
  status: "vulnerable"
  docs: "https://docs.example.com"
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Adding New Fingerprints

1. Fork the repository
2. Add your fingerprint to `fingerprints.yaml`
3. Test with a real domain (if possible)
4. Submit a Pull Request

### Reporting Issues

- Use the GitHub Issues tab
- Include the domain (redacted if sensitive)
- Attach relevant log files
- Describe expected vs actual behavior

### Development

```bash
# Enable debug mode during development
./subtake.sh --debug example.com

# Run shellcheck for linting
shellcheck subtake.sh
```

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. 

- ✅ Use on domains you own
- ✅ Use with written permission
- ✅ Use in bug bounty programs (check scope)
- ❌ Do NOT use for unauthorized access
- ❌ Do NOT use for malicious purposes

**The authors are not responsible for misuse of this tool.**

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Fingerprint research
- [projectdiscovery](https://github.com/projectdiscovery) - Amazing recon tools
- [OWASP Amass](https://github.com/owasp-amass/amass) - Subdomain enumeration
- The bug bounty community for continuous research

---

<p align="center">
  <strong>Made with ❤️ for the security community</strong>
</p>

<p align="center">
  <a href="https://github.com/W4RRR/subtake/stargazers">⭐ Star this repo</a> •
  <a href="https://github.com/W4RRR/subtake/issues">🐛 Report Bug</a> •
  <a href="https://github.com/W4RRR/subtake/pulls">🔀 Submit PR</a>
</p>

