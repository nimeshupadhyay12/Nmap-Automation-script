import nmap
import json
import yaml
import os
import sys
import logging
from ipaddress import ip_address, ip_network
import requests
import argparse
from colorama import init, Fore, Style

# Initialize colorama
init()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkScanner:
    def __init__(self, exploit_db_api_key=None):
        self.nm = nmap.PortScanner()
        self.results = {}
        self.all_scan_types = ['-sS', '-sU', '-sV', '-O', '-A', '--script vuln', '-sT', '-sP', '-sN', '-sF', '-sX']
        self.exploit_db_api_key = exploit_db_api_key
        self.static_exploit_db = {
            "Apache 2.4.41": "CVE-2021-41773 - Path Traversal (Exploit-DB ID: 50511)",
            "OpenSSH 7.9p1": "No direct exploit, try brute-force or check misconfigs",
            "telnet": "Default credentials or protocol sniffing",
            "http": "Check for directory traversal or outdated versions",
            "ssh": "Brute-force or check for weak keys",
            "https": "Test for SSL misconfigs or outdated versions"
        }

    def validate_ip(self, ip):
        try:
            ip_network(ip, strict=False) if '/' in ip else ip_address(ip)
            return True
        except ValueError:
            return False

    def scan(self, ip, ports='1-65535', scan_type='-sV', verbose=False):
        if not self.validate_ip(ip):
            logging.error(f"Invalid IP or network: {ip}")
            return False
        
        try:
            logging.info(f"Scanning {ip} on ports {ports} with {scan_type}...")
            args = f"{scan_type} --open" if not verbose else f"{scan_type} -v --open"
            self.nm.scan(ip, ports, arguments=args)
            self.results[ip] = self.nm._scan_result
            return True
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            return False

    def total_scan(self, ip, ports='1-65535', verbose=False):
        success = False
        for scan_type in self.all_scan_types:
            if self.scan(ip, ports, scan_type, verbose):
                success = True
            else:
                logging.warning(f"Scan type {scan_type} failed, continuing...")
        return success

    def smart_scan(self, ip, ports='1-65535', scan_type='quick', verbose=False):
        if scan_type == 'total':
            return self.total_scan(ip, ports, verbose)
        return self.scan(ip, ports, scan_type, verbose)

    def check_vulnerability(self, service, version):
        if version == 'N/A':
            return None
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['totalResults'] > 0:
                    return f"Found {data['totalResults']} potential vulnerabilities"
            return None
        except Exception as e:
            logging.error(f"Vulnerability check failed: {e}")
            return None

    def suggest_exploit(self, service, version):
        key = f"{service} {version}" if version != 'N/A' else service
        
        if self.exploit_db_api_key:
            try:
                url = "https://www.exploit-db.com/api/v1/exploits"
                headers = {"Authorization": f"Bearer {self.exploit_db_api_key}"}
                params = {"query": key, "type": "search"}
                response = requests.get(url, headers=headers, params=params, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("results"):
                        exploit = data["results"][0]
                        return f"{exploit.get('title', 'Exploit found')} (EDB-ID: {exploit.get('id', 'N/A')})"
                    return "No exploits found via API."
                else:
                    logging.error(f"Exploit-DB API error: {response.status_code}")
            except Exception as e:
                logging.error(f"Exploit-DB API call failed: {e}")
        
        return self.static_exploit_db.get(key, "No known exploits - try 'searchsploit' manually")

    def try_exploit(self, ip, port, service):
        if service == 'ssh' and port == 22:
            return "Try SSH login with 'root:admin', 'user:password', or use Hydra"
        elif service == 'telnet' and port == 23:
            return "Try Telnet with 'admin:admin', 'root:root', or sniff creds"
        elif service in ['http', 'https'] and port in [80, 443]:
            return "Test directory traversal (e.g., /etc/passwd) or use Burp Suite"
        return "No quick exploit available - research further"

    def next_step(self, open_ports):
        if not open_ports:
            return "No open ports - try a broader scan (e.g., UDP) or evasion techniques."
        steps = []
        has_ssh = any(p[0] == 22 for p in open_ports)
        has_web = any(p[0] in [80, 443] for p in open_ports)
        has_telnet = any(p[0] == 23 for p in open_ports)

        if has_ssh:
            steps.append("Brute-force SSH with Hydra or check weak keys with ssh-audit.")
        if has_web:
            steps.append("Scan web server with Nikto or OWASP ZAP for vulns.")
        if has_telnet:
            steps.append("Sniff Telnet traffic with Wireshark for creds.")
        if len(open_ports) > 1:
            steps.append("Combine services for privilege escalation (e.g., SSH + web).")
        steps.append("Search Exploit-DB or Metasploit for version-specific exploits.")
        return steps

    def summarize_results(self, ip, goal='quick'):
        if ip not in self.nm.all_hosts():
            print(f"\n{Fore.RED}[!] No info for {ip} - is it down or blocked?{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}===== Scan Report for {ip} ====={Style.RESET_ALL}")
        print(f"  Target Name: {self.nm[ip].hostname() or 'Unknown'}")
        status = "Up and running" if self.nm[ip].state() == 'up' else "Down or hiding"
        print(f"  Status: {status}")

        print(f"\n{Fore.YELLOW}--- System Details ---{Style.RESET_ALL}")
        if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
            os_info = self.nm[ip]['osmatch'][0]
            print(f"  System: {os_info['name']} ({os_info['accuracy']}% sure)")
        else:
            print(f"  System: Couldn’t tell")

        open_ports = []
        common_ports = {
            21: "File sharing (FTP)",
            22: "Remote login (SSH)",
            23: "Old remote login (Telnet)",
            25: "Email sending (SMTP)",
            53: "Internet names (DNS)",
            80: "Web (HTTP)",
            443: "Secure web (HTTPS)",
            445: "Windows sharing (SMB)",
            3389: "Remote desktop (RDP)"
        }
        risky_ports = {23: "Telnet - old and risky", 445: "SMB - easy to hack"}

        for proto in self.nm[ip].all_protocols():
            ports = self.nm[ip][proto].keys()
            for port in sorted(ports):
                service = self.nm[ip][proto][port]['name']
                state = self.nm[ip][proto][port]['state']
                version = self.nm[ip][proto][port].get('version', 'N/A')
                if state == 'open':
                    open_ports.append((port, proto, service, version))

        print(f"\n{Fore.GREEN}--- Open Ports ---{Style.RESET_ALL}")
        print(f"  Found: {len(open_ports)} open")
        if open_ports:
            print("  What’s exposed:")
            for port, proto, service, version in open_ports:
                explanation = common_ports.get(port, "Unknown - custom app?")
                version_info = f" ({version})" if version != 'N/A' else ""
                print(f"    • Port {port}: {service}{version_info} - {explanation}")
        else:
            print(f"  Nothing’s open - target looks locked down.")

        if 'hostscript' in self.nm[ip]:
            print(f"\n{Fore.YELLOW}--- Bonus Info ---{Style.RESET_ALL}")
            for script in self.nm[ip]['hostscript']:
                print(f"    • {script['id']}: {script['output']}")

        print(f"\n{Fore.MAGENTA}--- Hack It! ---{Style.RESET_ALL}")
        if not open_ports:
            print("  • No weak spots found yet.")
        else:
            print("  Attack options:")
            for port, _, service, version in open_ports:
                if port in risky_ports:
                    print(f"    • Port {port} ({service}): {risky_ports[port]} - Hit it hard!")
                vuln = self.check_vulnerability(service, version)
                if vuln:
                    print(f"    • Port {port} ({service} {version}): {vuln} - Ripe for attack!")
                exploit = self.suggest_exploit(service, version)
                print(f"    • Port {port}: Exploit Idea - {exploit}")
                attempt = self.try_exploit(ip, port, service)
                print(f"    • Port {port}: Quick Attack - {attempt}")

        print(f"\n{Fore.RED}--- What’s Next? ---{Style.RESET_ALL}")
        next_steps = self.next_step(open_ports)
        if isinstance(next_steps, str):
            print(f"  • {next_steps}")
        else:
            print("  Your attack plan:")
            for step in next_steps:
                print(f"    • {step}")

        print(f"\n{Fore.CYAN}===== Report Done ====={Style.RESET_ALL}")

    def save_results(self, filename, format='json'):
        if not self.results:
            logging.error("No results to save.")
            return
        with open(filename, 'w') as f:
            if format == 'json':
                json.dump(self.results, f, indent=4)
            elif format == 'txt':
                f.write(self.nm.csv())
            elif format == 'csv':
                f.write(self.nm.csv())
        logging.info(f"Results saved to {filename}")

    def check_vulnerabilities(self, ip):
        if ip not in self.nm.all_hosts():
            return
        for proto in self.nm[ip].all_protocols():
            for port in self.nm[ip][proto].keys():
                service = self.nm[ip][proto][port]['name']
                version = self.nm[ip][proto][port].get('version', 'N/A')
                if version != 'N/A':
                    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={service}+{version}"
                    logging.info(f"Check vulnerabilities for {service} {version} at: {url}")

def load_config(config_file='config.yaml'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    return {}

def get_user_input():
    scanner = NetworkScanner()
    
    while True:
        ip = input("Enter target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24): ").strip()
        if scanner.validate_ip(ip):
            break
        print("Bad IP or range - try again.")

    ports = input("Ports to scan (press Enter for all 1-65535): ").strip() or '1-65535'

    scan_options = {
        "Basic Scans": {
            "1": ("-sP", "Quick Peek (-sP) - Fast check if it’s alive"),
            "2": ("-sT", "Loud Connect (-sT) - Simple and loud connect scan"),
            "3": ("-O", "OS Guess (-O) - Guess the target’s system")
        },
        "Stealth Scans": {
            "4": ("-sS", "SYN Stealth (-sS) - Fast and sneaky TCP scan"),
            "5": ("-sN", "Null Stealth (-sN) - Super stealthy, no flags"),
            "6": ("-sF", "FIN Stealth (-sF) - Stealth scan with FIN flag"),
            "7": ("-sX", "Xmas Stealth (-sX) - Stealth scan with odd flags"),
            "8": ("-sU", "UDP Stealth (-sU) - Quiet UDP port check")
        },
        "Advanced Scans": {
            "9": ("-sV", "Service Probe (-sV) - What’s running on ports?"),
            "10": ("--script vuln", "Vuln Hunt (--script vuln) - Scan for known weaknesses"),
            "11": ("-A", "All-In Assault (-A) - Everything at once"),
            "12": ("-sV -O", "Deep Sweep (-sV -O) - Full service and OS combo"),
            "13": ("total", "Total Blitz (all flags) - Hit it with every scan type")
        }
    }

    print("\nPick your scan:")
    for category, options in scan_options.items():
        print(f"\n{category}:")
        for key, (scan_type, desc) in options.items():
            print(f"  {key}: {desc}")

    while True:
        choice = input("\nEnter scan number (1-13): ").strip()
        for options in scan_options.values():
            if choice in options:
                scan_type = options[choice][0]
                break
        else:
            print("Wrong number - pick 1 to 13.")
            continue
        break

    return ip, ports, scan_type

def main():
    parser = argparse.ArgumentParser(description="Easy Nmap Scanner for Recon and Attack")
    parser.add_argument("--output", help="Save results to a file")
    parser.add_argument("--format", default="json", choices=["json", "txt", "csv"], help="File format")
    parser.add_argument("--verbose", action="store_true", help="Show extra details")
    parser.add_argument("--config", default="config.yaml", help="Config file")
    parser.add_argument("--api-key", help="Exploit-DB API key (optional)")
    args = parser.parse_args()

    config = load_config(args.config)
    scanner = NetworkScanner(exploit_db_api_key=args.api_key or config.get('exploit_db_api_key'))

    ip, ports, scan_type = get_user_input()

    print(f"\n{Fore.YELLOW}Scanning {ip}... Hold tight!{Style.RESET_ALL}")
    if scanner.smart_scan(ip, ports, scan_type, args.verbose):
        scanner.summarize_results(ip, goal=scan_type)

    if args.output:
        scanner.save_results(args.output, args.format)
    
    scanner.check_vulnerabilities(ip)

if __name__ == "__main__":
    main()
