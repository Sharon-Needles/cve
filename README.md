# cve.sh — CVE Discovery & Exploitation Reporter

**Technology fingerprinting → version extraction → NVD/CISA KEV lookup → exploit discovery → safe validation → evidence capture. Produces a ready-to-submit bug bounty report when a CVE chain is demonstrated.**

---

## Features

### 6-Phase Pipeline

| Phase | Script | What It Does |
|-------|--------|--------------|
| 1 | `cve_extract_tech.py` | WhatWeb + httpx + nmap → tech fingerprint per host |
| 2 | `cve_version_map.py` | Normalize versions to CPE format for NVD querying |
| 3 | `cve_lookup.py` | Query NVD API + CISA KEV + match nuclei CVE templates |
| 4 | `cve_exploit_search.py` | searchsploit + GitHub PoC search for matched CVEs |
| 5 | `cve_validate.py` | Non-destructive safe validation (confirm handler exists, respond correctly) |
| 6 | `cve_evidence.py` + `cve_report.py` | Capture curl evidence, screenshots, produce Markdown report |

**Also:** `cve_summary.py` — generates executive summary across all CVEs found.

### Quality
- **CISA KEV integration** — Flags CVEs on the Known Exploited Vulnerabilities catalog (highest priority)
- **Non-destructive** — Never runs actual exploits; confirms existence of vulnerable surface only
- **Resume support** — Restart from any phase
- **Integrates with hunt.sh** — `--hunt-dir` imports from an existing hunt output directory
- **VRT-aware output** — Findings tagged, impact_gate.py applied before report

---

## Requirements

### Required
```bash
sudo pacman -S curl jq whatweb nmap python3
pip install requests          # or: pacman -S python-requests
```

### Recommended
```bash
sudo pacman -S nuclei
pip install bs4 lxml          # HTML parsing for tech fingerprint
```

### Optional
```bash
sudo pacman -S searchsploit   # Exploit database search (phase 4)
```

---

## Installation

```bash
git clone https://github.com/Sharon-Needles/cve
cd cve
chmod +x cve.sh
pip install -r requirements.txt  # (if provided)

# Global symlink (optional)
sudo ln -s "$(pwd)/cve.sh" /usr/local/bin/cve
```

---

## Quick Start

### Scan Domain List
```bash
./cve.sh --target "Acme Corp" --domains scope.txt --platform bugcrowd
```

### Scan Single URL
```bash
./cve.sh --target "Acme" --url https://erp.example.com --platform bugcrowd
```

### Import from hunt.sh Output
```bash
./cve.sh --target "Acme" --hunt-dir ./hunts/Acme_Corp_20260423_120000 --platform bugcrowd
```

### Resume
```bash
./cve.sh --resume ./hunts/Acme_CVE_20260423_120000
```

---

## Usage

```
cve.sh [OPTIONS]

Required (one of):
  -d, --domains FILE     Domain list (one per line)
  -u, --url URL          Single target URL
  --hunt-dir DIR         Import tech fingerprint from hunt.sh output

Options:
  -t, --target NAME      Target/program name (for output dir)
  -p, --platform NAME    bugcrowd | hackerone | other
  -o, --out DIR          Output directory (default: ./hunts)
  --resume DIR           Resume from existing output
  --max-hosts N          Max hosts for deep nmap scan (default: 200)
  --nmap-ports N         Nmap top-N ports (default: 100)
  -h, --help             Show help
```

### Examples

**Quick scan on API server:**
```bash
cve --target "Target" -u https://api.example.com/admin --platform hackerone
```

**Full domain list — import from hunt:**
```bash
cve --target "Target" --hunt-dir ./hunts/Target_20260423_120000 --platform bugcrowd
```

**Resume after interruption:**
```bash
cve --resume ./hunts/Target_CVE_20260423_120000
```

---

## Output Structure

```
Acme_Corp_CVE_20260423_120000/
├── manifest.json
├── timeline.log
│
├── cves/
│   ├── tech_fingerprint.json      # whatweb + httpx + nmap per host
│   ├── version_map.json           # Normalized CPE identifiers
│   ├── cve_matches.json           # NVD query results
│   ├── kev_matches.json           # CISA KEV matches (highest priority)
│   ├── nuclei_cve_results.json    # Nuclei CVE template hits
│   ├── exploits.json              # searchsploit + GitHub PoC results
│   ├── validation_results.json    # Non-destructive confirmation results
│   └── evidence/
│       ├── *.curl.txt             # curl command + full response
│       └── *.screenshot.png       # (if tool available)
│
├── findings.txt                   # All CVE findings
├── validated_findings.txt         # CVEs with confirmed vulnerable surface
├── [SUBMIT:P1].txt               # KEV CVEs with confirmed exploitation surface
├── [SUBMIT:P2].txt               # High CVSS CVEs confirmed present
├── [SUBMIT:P3].txt               # Medium CVEs confirmed
├── [REVIEW:P4].txt               # Unconfirmed CVEs (version match only)
├── [DO_NOT_SUBMIT:P5].txt        # Version disclosure without CVE chain
└── report.md                      # Full Bugcrowd/H1 report
```

---

## CVE Research Workflow

The tool follows this pattern automatically — understanding it helps interpret output:

1. **Fingerprint** the technology stack (`WordPress 6.1`, `Apache 2.4.49`, `ServiceNow Madrid`)
2. **Map to CPE** (`cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`)
3. **Query NVD** for all CVEs matching that CPE — filter by CVSS score
4. **Cross-reference CISA KEV** — if it's KEV, highest priority
5. **Find exploit PoC** — searchsploit, nuclei templates, GitHub
6. **Validate safely** — confirm the endpoint/handler responds as expected for the CVE
7. **Evidence capture** — screenshot, curl output showing version header
8. **Generate report** — full Markdown with CVSS score, KEV status, PoC curl, timeline

---

## What Makes a Submittable CVE Finding

The tool categorizes automatically, but the rule is:

**Submit when you can demonstrate:**
- The technology version is confirmed on the target (version from header, banner, error page)
- The specific CVE affects that version range
- The vulnerable endpoint/handler exists and responds (non-destructive check)
- CVSS score ≥ 6.0 OR CVE is on CISA KEV list

**Do NOT submit:**
- Version disclosure alone without a CVE → P5, informational
- CVE listing without confirmed version → theoretical
- Outdated software without exploitable CVE → always rejected
- You must PROVE the surface exists — not just that the CVE exists

### Example Strong Finding
```
Apache Struts 2.5.25 running on api.example.com (confirmed via Server header).
CVE-2021-31805 (CVSS 9.8, CISA KEV) affects Struts < 2.5.30.
Endpoint /struts2-rest-showcase/orders/3 responds to REST requests.
Nuclei CVE template confirms vulnerable.
```

### Example Weak Finding (Don't Submit)
```
Server: Apache/2.4.18 detected on example.com.
CVE-2021-41773 affects Apache 2.4.49 only.
Version doesn't match — not vulnerable.
```

---

## Integration

### Import from hunt.sh
hunt.sh phases 1–3 run WhatWeb and httpx fingerprinting. Import those results:
```bash
cve --target "Target" --hunt-dir ./hunts/Target_Corp_20260423_120000
```
Skips re-fingerprinting, jumps straight to CVE lookup.

### Chain with access.sh
If CVE reveals an authentication bypass or admin interface:
```bash
access --target "Target" -d vulnerable.example.com --platform bugcrowd
```

### ServiceNow / Known App CVEs
For known platforms found in fingerprint:
- ServiceNow: Map build tag to CVE via KB advisories
- Telerik UI: CDN URL version → check CVE-2019-18935, CVE-2024-6327
- Struts: Version header → check CVE-2023-50164, CVE-2021-31805

---

## Troubleshooting

### Phase 3 (CVE Lookup) is slow
NVD API rate limits to 5 requests/second without API key. Add one:
```bash
export NVD_API_KEY="your_key_from_nvd.nist.gov"
```

### "No versions extracted"
WhatWeb may not detect the version from the homepage. Point it at specific paths:
```bash
./cve.sh --target "Test" -u https://example.com/admin/login --platform bugcrowd
```

### Nuclei CVE templates not running
Ensure templates are up to date:
```bash
nuclei -update-templates
ls ~/nuclei-templates/cves/ | wc -l
```

### Phase 6 (Evidence) screenshot fails
Screenshot tools (gowitness, cutycapt) are optional. curl evidence still captured.

---

## Tested On

- **OS**: BlackArch Linux, Ubuntu 22.04
- **Bash**: 5.x
- **Python**: 3.10+
- **nuclei**: v3.7+

---

## License

MIT

---

## Disclaimer

Only run against authorized targets. Non-destructive validation means confirming the surface exists — never trigger the CVE payload. Follow responsible disclosure guidelines for all findings.
