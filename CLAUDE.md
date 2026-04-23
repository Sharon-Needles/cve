# CLAUDE.md — cve.sh

CVE discovery & exploitation — fingerprinting, NVD lookup, CISA KEV, exploit discovery, PoC generation.

## What It Does

6-phase CVE discovery and exploitation:
1. Technology fingerprinting (whatweb, httpx, nmap)
2. Version extraction & normalization (CPE)
3. CVE lookup (NVD, CISA KEV, nuclei templates)
4. Exploit discovery (searchsploit, GitHub)
5. Safe validation (non-destructive version checks)
6. Evidence capture (screenshots, responses)

---

## Quick Commands

```bash
cve --target "Target" --domains scope.txt
cve --target "Target" -u https://example.com
cve --resume ./hunts/Target_CVE_*
```

---

MIT License.
