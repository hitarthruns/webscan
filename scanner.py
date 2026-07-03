# scanner.py
import requests
import json
from urllib.parse import urlparse
from crawler import WebCrawler
from sqli import SQLiDetector
from xss import XSSDetector
from traversal import TraversalDetector
import sys

class VulnerabilityScanner:
    def __init__(self, target_url, max_pages=50):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.max_pages = max_pages
        self.results = {
            'target': target_url,
            'sqli': [],
            'xss': [],
            'traversal': [],
            'summary': {}
        }

    def load_payloads(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Payload file not found: {filepath}")
            return []

    def run(self):
        print(f"[*] Starting scan against {self.target_url}")
        print(f"[*] Phase 1: Crawling...")
        
        crawler = WebCrawler(self.target_url, self.session, self.max_pages)
        discovered = crawler.crawl()
        
        print(f"    Discovered: {len(discovered['urls'])} URLs, {len(discovered['forms'])} forms, {len(discovered['params'])} params")
        
        # Load payloads
        sqli_payloads = self.load_payloads('payloads/sqli.txt')
        xss_payloads = self.load_payloads('payloads/xss.txt')
        traversal_payloads = self.load_payloads('payloads/traversal.txt')
        
        # Initialize detectors
        sqli_detector = SQLiDetector(self.session)
        xss_detector = XSSDetector(self.session)
        traversal_detector = TraversalDetector(self.session)
        
        # Phase 2: Test URL parameters
        print(f"[*] Phase 2: Testing URL parameters...")
        for url in discovered['urls']:
            # Get params for this specific URL
            params = [p for u, p in discovered['params'] if u == url]
            if not params:
                continue
            
            print(f"    Testing {url} ({len(params)} params)")
            
            sqli_findings = sqli_detector.test_url_params(url, params, sqli_payloads)
            self.results['sqli'].extend(sqli_findings)
            
            xss_findings = xss_detector.test_url_params(url, params, xss_payloads)
            self.results['xss'].extend(xss_findings)
            
            traversal_findings = traversal_detector.test_url_params(url, params, traversal_payloads)
            self.results['traversal'].extend(traversal_findings)
        
        # Phase 3: Test forms
        print(f"[*] Phase 3: Testing forms...")
        for form in discovered['forms']:
            print(f"    Testing form at {form[0]}")
            
            sqli_findings = sqli_detector.test_form_fields(form, sqli_payloads)
            self.results['sqli'].extend(sqli_findings)
            
            xss_findings = xss_detector.test_form_fields(form, xss_payloads)
            self.results['xss'].extend(xss_findings)
            
            traversal_findings = traversal_detector.test_form_fields(form, traversal_payloads)
            self.results['traversal'].extend(traversal_findings)
        
        # Phase 4: Generate summary
        self._generate_summary()
        self._print_report()
        self._generate_html_report()
        
        return self.results

    def _generate_summary(self):
        self.results['summary'] = {
            'total_sqli': len(self.results['sqli']),
            'total_xss': len(self.results['xss']),
            'total_traversal': len(self.results['traversal']),
            'total_vulnerabilities': len(self.results['sqli']) + len(self.results['xss']) + len(self.results['traversal']),
        }

    def _print_report(self):
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        
        print(f"\n[+] SQL Injection: {self.results['summary']['total_sqli']} found")
        for finding in self.results['sqli']:
            print(f"    - {finding['url']} | Param: {finding['param']} | Type: {finding['type']}")
            print(f"      Payload: {finding['payload']}")
        
        print(f"\n[+] XSS: {self.results['summary']['total_xss']} found")
        for finding in self.results['xss']:
            print(f"    - {finding['url']} | Param: {finding['param']} | Type: {finding['type']}")
            print(f"      Payload: {finding['payload']}")
        
        print(f"\n[+] Directory Traversal: {self.results['summary']['total_traversal']} found")
        for finding in self.results['traversal']:
            print(f"    - {finding['url']} | Param: {finding['param']} | Type: {finding['type']}")
            print(f"      Payload: {finding['payload']}")

    def _generate_html_report(self):
        html = f"""<!DOCTYPE html>
<html>
<head><title>Vulnerability Scan Report - {self.target_url}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
h1 {{ color: #d44; }}
.vuln {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
.critical {{ border-left: 5px solid #d44; }}
.payload {{ background: #f5f5f5; padding: 5px; font-family: monospace; }}
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
<p>Target: {self.target_url}</p>
<p>Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<h2>Summary</h2>
<ul>
<li>SQL Injection: {self.results['summary']['total_sqli']}</li>
<li>XSS: {self.results['summary']['total_xss']}</li>
<li>Directory Traversal: {self.results['summary']['total_traversal']}</li>
<li><strong>Total: {self.results['summary']['total_vulnerabilities']}</strong></li>
</ul>

<h2>SQL Injection Findings</h2>
{self._findings_to_html(self.results['sqli'], 'SQLi')}

<h2>XSS Findings</h2>
{self._findings_to_html(self.results['xss'], 'XSS')}

<h2>Directory Traversal Findings</h2>
{self._findings_to_html(self.results['traversal'], 'Traversal')}
</body>
</html>"""
        
        with open('report.html', 'w') as f:
            f.write(html)
        print("\n[*] HTML report saved to report.html")

    def _findings_to_html(self, findings, vuln_type):
        if not findings:
            return "<p>No vulnerabilities found.</p>"
        html = ""
        for f in findings:
            html += f'''<div class="vuln critical">
<h3>{vuln_type} at {f['url']}</h3>
<p><strong>Parameter:</strong> {f['param']}</p>
<p><strong>Type:</strong> {f['type']}</p>
<p><strong>Payload:</strong> <span class="payload">{f['payload']}</span></p>
</div>'''
        return html


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_url> [max_pages]")
        sys.exit(1)
    
    target = sys.argv[1]
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    scanner = VulnerabilityScanner(target, max_pages)
    results = scanner.run()