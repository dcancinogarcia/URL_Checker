import re
import urllib.parse
import socket
import ssl
from datetime import datetime
from difflib import SequenceMatcher


class URLAnalyzer:
    def __init__(self, url):
        self.original_url = url.strip()
        self.url = self._normalize_url(url)
        self.parsed = urllib.parse.urlparse(self.url)
        self.warnings = []
        self.risk_score = 0

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url

    # ---------- Checks ----------

    def check_scheme(self):
        if self.parsed.scheme == 'http':
            self.warnings.append("URL uses HTTP (unencrypted connection).")
            self.risk_score += 2

    def check_direct_ip(self):
        hostname = self.parsed.hostname or ''
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, hostname):
            self.warnings.append("URL uses an IP address instead of a domain.")
            self.risk_score += 3

    def check_length(self):
        length = len(self.original_url)
        if length > 100:
            self.warnings.append(f"Unusually long URL ({length} characters).")
            self.risk_score += 2
        elif length > 75:
            self.risk_score += 1

    def check_suspicious_symbols(self):
        if '@' in self.original_url:
            self.warnings.append("The '@' symbol can hide the real domain.")
            self.risk_score += 3

        if self.original_url.count('//') > 1 and self.parsed.scheme in ('http', 'https'):
            self.warnings.append("Multiple '//' may indicate redirection.")
            self.risk_score += 2

        hostname = self.parsed.hostname or ''
        if hostname.count('-') >= 3:
            self.warnings.append("Too many hyphens may imitate legitimate domains.")
            self.risk_score += 2

    def check_subdomains(self):
        hostname = self.parsed.hostname or ''
        parts = hostname.split('.')
        if len(parts) > 4:
            self.warnings.append(f"High number of subdomains ({len(parts)} levels).")
            self.risk_score += 2

    def check_keywords(self):
        keywords = ['login', 'verify', 'update', 'secure', 'account',
                    'signin', 'confirm', 'banking', 'password', 'urgent']
        url_lower = self.original_url.lower()
        found = [k for k in keywords if k in url_lower]
        if found:
            self.warnings.append(f"Contains suspicious keywords: {', '.join(found)}")
            self.risk_score += len(found)

    def check_typosquatting(self):
        popular_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'netflix.com', 'paypal.com', 'instagram.com',
            'twitter.com', 'youtube.com', 'whatsapp.com', 'gmail.com',
            'chase.com', 'wellsfargo.com', 'bankofamerica.com'
        ]
        hostname = (self.parsed.hostname or '').lower().replace('www.', '')

        for domain in popular_domains:
            similarity = SequenceMatcher(None, hostname, domain).ratio()
            if 0.75 < similarity < 1.0:
                self.warnings.append(
                    f"Possible typosquatting: '{hostname}' resembles '{domain}'."
                )
                self.risk_score += 5
                break

    def check_suspicious_extension(self):
        extensions = ['.exe', '.apk', '.scr', '.bat', '.cmd', '.msi',
                      '.zip', '.rar', '.js', '.vbs']
        path = self.parsed.path.lower()
        for ext in extensions:
            if path.endswith(ext):
                self.warnings.append(f"Downloads a potentially dangerous file: {ext}")
                self.risk_score += 4
                break

    def check_server(self):
        try:
            hostname = self.parsed.hostname
            port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)

            # DNS check
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror:
                self.warnings.append("Domain does not resolve (does not exist or is down).")
                self.risk_score += 5
                return

            # SSL certificate check
            if self.parsed.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            expires = cert.get('notAfter')
                            if expires:
                                exp_date = datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
                                if exp_date < datetime.now():
                                    self.warnings.append("SSL certificate is expired.")
                                    self.risk_score += 5
                except ssl.SSLError as e:
                    self.warnings.append(f"SSL certificate error: {e}")
                    self.risk_score += 5
                except (socket.timeout, socket.error, ConnectionRefusedError):
                    self.warnings.append(" Could not verify SSL certificate (timeout).")
                    self.risk_score += 1

        except Exception as e:
            self.warnings.append(f"Error while checking the server: {e}")

    def check_url_shorteners(self):
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                      'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'cutt.ly']
        hostname = (self.parsed.hostname or '').lower()
        if any(hostname.endswith(s) for s in shorteners):
            self.warnings.append("It is a shortened link (real destination hidden).")
            self.risk_score += 3

    # ---------- Full Analysis ----------

    def analyze(self):
        print(f"\n{'='*60}")
        print(f"Analyzing: {self.original_url}")
        print(f"{'='*60}\n")

        self.check_scheme()
        self.check_direct_ip()
        self.check_length()
        self.check_suspicious_symbols()
        self.check_subdomains()
        self.check_keywords()
        self.check_typosquatting()
        self.check_suspicious_extension()
        self.check_url_shorteners()
        self.check_server()

        # Show warnings
        if self.warnings:
            print("Findings:")
            for w in self.warnings:
                print(f"  {w}")
            print()
        else:
            print("No suspicious signs found.\n")

        # Final verdict
        print(f"{'='*60}")
        if self.risk_score == 0:
            print("VERDICT: SAFE URL")
            print("   No obvious threats detected.")
        elif self.risk_score <= 3:
            print("VERDICT: LOW RISK")
            print("   Be cautious before opening this link.")
        elif self.risk_score <= 7:
            print("VERDICT: MEDIUM RISK")
            print("   It is not recommended to open this link without verifying the source.")
        else:
            print("VERDICT: DANGEROUS URL")
            print("   DO NOT open this link!")
        print(f"   Risk score: {self.risk_score}")
        print(f"{'='*60}\n")

        return self.risk_score


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          URL SECURITY ANALYZER - PYTHON                  ║")
    print("╚══════════════════════════════════════════════════════════╝")

    while True:
        url = input("\nEnter a URL (or 'exit' to quit): ").strip()
        if url.lower() in ('exit', 'quit', ''):
            print("Goodbye!")
            break

        try:
            analyzer = URLAnalyzer(url)
            analyzer.analyze()
        except Exception as e:
            print(f"Error analyzing the URL: {e}")


if __name__ == "__main__":
    main()