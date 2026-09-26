# URL Security Analyzer

A heuristic URL analyzer written in Python that inspects links for common phishing, malware, and typosquatting indicators. It combines static pattern analysis with live DNS and SSL certificate checks to produce a risk score and a clear verdict.

---

## Features

- **Multi-layer analysis** — combines string/heuristic checks with live server-side verification
- **DNS resolution check** — detects domains that do not resolve (non-existent or down)
- **SSL certificate inspection** — flags expired certificates or TLS handshake errors
- **Typosquatting detection** — uses `difflib.SequenceMatcher` to compare against popular domains
- **URL shortener detection** — recognizes services like `bit.ly`, `tinyurl.com`, `t.co`, and more
- **Suspicious keyword scanning** — looks for terms like `login`, `verify`, `account`, `urgent`
- **Dangerous file extension detection** — flags links ending in `.exe`, `.apk`, `.scr`, `.js`, etc.
- **Weighted risk scoring** — each finding contributes a different weight to an overall score
- **Clear verdict output** — SAFE, LOW RISK, MEDIUM RISK, or DANGEROUS URL
- **Interactive CLI** — analyze URLs in a loop until you type `exit` or `quit`
- **No third-party dependencies** — standard library only

---

## Requirements

- Python **3.6+**
- No external packages — uses only `re`, `urllib.parse`, `socket`, `ssl`, `datetime`, and `difflib`

---

## Usage

Clone the repository and run the script:

```bash
git clone https://github.com/dcancinogarcia/url-checker.git
cd url-checker
python URL_Checker.py
```
---

Once running, you'll see the banner and a prompt:
```bash
╔══════════════════════════════════════════════════════════╗
║          URL SECURITY ANALYZER - PYTHON                  ║
╚══════════════════════════════════════════════════════════╝

Enter a URL (or 'exit' to quit):

```

Type any URL (with or without a scheme — https:// is added automatically):

```bash
Enter a URL (or 'exit' to quit): paypa1-secure-login.verify-account.com

```

Example output:

```bash
============================================================
Analyzing: paypa1-secure-login.verify-account.com
============================================================

Findings:
  Contains suspicious keywords: login, verify, secure, account
  Possible typosquatting: 'paypa1-secure-login.verify-account.com' resembles 'paypal.com'.
  Too many hyphens may imitate legitimate domains.

============================================================
VERDICT: DANGEROUS URL
   DO NOT open this link!
   Risk score: 13
============================================================

```

Type **exit**, **quit** or press Enter on an empty line to stop.

---

## Risk Scoring
Each check adds a weighted value to risk_score. The final verdict is derived as follows:

| Score        | Veredict        | Description                              |
|--------------|-----------------|------------------------------------------|
| `0`          | `SAFE URL`      | No obvious threats detected              |
| `1 - 3`      | `LOW RISK`      | Be cautious before opening               |
| `4 - 7`      | `MEDIUM RISK`   | Verify the source before opening         |
| `>7`         | `DANGEROUS URL` | Do not open this link                    |



## Check weights

| Check                            | Weight       | 
|----------------------------------|-----------------|
| `HTTP instead of HTTPS`          | +2    |
| `Direct IP address as host`      | +3    | 
| `URL length > 100 chars`         | +2    |
| `URL length > 75 chars`          | +1    | 
| `@ symbol in URL`                | +3    |
| `Multiple // in URL`             | +2    | 
| `≥ 3 hyphens in hostname`        | +2    |
| `> 4 subdomain levels`           | +2    | 
| `Suspicious keywords`            | +1 each |
| `Typo squatting match`           | +5    | 
| `Dangerous file extension`       | +4    |
| `Domain does not resolve`        | +5    | 
| `Expired SSL certificate`        | +5    |
| `SSL error`                      | +5    | 
| `SSL verification timeout`       | +1    |
| `URL shortener`                  | +3    | 


## Configuration
You can extend the analyzer by editing the lists inside URLAnalyzer:

| Attribute                            | Location       | Description      | 
|--------------------|-----------------|-----------------|
| `popular_domains` | `check_typosquatting()`| Domains to compare against for typosquatting |
| `keywords`        | `check_keywords()`     | Suspicious terms to search for in the URL   |
| `extensions`      | `check_suspicious_extension()`     | File extensions flagged as dangerous |
| `shorteners`      | `check_url_shorteners()`     | Known URL shortener domains |
| `Similarity` threshold 0.75     | `check_typosquatting()`     | Minimum ratio to flag a domain as a lookalike |


---

## You can also use the class directly in your own code:

```python
from URL_Checker import URLAnalyzer

analyzer = URLAnalyzer("https://example.com")
score = analyzer.analyze()
print(f"Risk score: {score}")
```

---

##  Security Notes

- The analyzer makes live network requests (DNS + TLS handshake). Results depend on your network and may time out.
- Timeouts are set to 5 seconds per connection to avoid hanging.
- Typosquatting detection uses a simple similarity ratio and may produce false positives for legitimately similar domains.
- This tool is a heuristic aid, not a guarantee. Always verify links through official sources before clicking.
- No URL is ever executed, downloaded, or rendered — only parsed and inspected.

>  Warning: Although this tool analyzes multiple indicators and generates a risk score, its results are for guidance only. False positives or false negatives may occur. Never rely solely on this analysis: always verify the URL's authenticity by accessing the official source, checking the exact domain, and avoiding links received via untrusted channels. If in doubt, do not open the link.

---

## How It Works
- Normalization — if the URL has no scheme, https:// is prepended.
- Static checks — the URL is inspected for scheme, IP host, length, symbols, subdomains, keywords, typosquatting, extensions, and shorteners.
- Live checks — DNS resolution and, for HTTPS, SSL certificate validity (including expiration).
- Scoring — each finding adds to risk_score.
- Verdict — the final score is mapped to one of four risk categories and printed to the console.
