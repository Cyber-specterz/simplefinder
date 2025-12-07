#!/data/data/com.termux/files/usr/bin/bash

echo "========================================="
echo "   SimpleFinder Termux Installer"
echo "   Author: Cyber-Specterz"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Update Termux
echo -e "${BLUE}[*] Updating Termux packages...${NC}"
pkg update -y && pkg upgrade -y

# Install required packages
echo -e "${BLUE}[*] Installing dependencies...${NC}"
pkg install python python-pip git curl wget dnsutils -y

# Install Python packages
echo -e "${BLUE}[*] Installing Python packages...${NC}"
pip install --upgrade pip
pip install requests

# Create directory
echo -e "${BLUE}[*] Setting up SimpleFinder...${NC}"
cd ~
mkdir -p simplefinder
cd simplefinder

# Create wordlist directory
mkdir -p wordlists results

# Create default wordlist
echo -e "${BLUE}[*] Creating wordlist...${NC}"
cat > wordlists/default.txt << EOF
www
mail
ftp
admin
api
dev
test
blog
shop
app
mobile
web
secure
portal
vpn
cdn
static
assets
media
download
upload
cpanel
webmail
smtp
pop
ns1
ns2
dns
mx
server
db
mysql
redis
git
docker
stage
prod
beta
alpha
demo
EOF

echo -e "${GREEN}[+] Wordlist created (40 entries)${NC}"

# Create SimpleFinder script
echo -e "${BLUE}[*] Setting up SimpleFinder...${NC}"
cat > simplefinder-termux.py << 'EOF'
#!/data/data/com.termux/files/usr/bin/python3
"""
SimpleFinder - Subdomain Scanner for Termux
Author: Cyber-Specterz
Version: 1.0.0 (Termux Edition)
"""

import sys
import os
import argparse
import requests
import json
import time
import socket
import re
import concurrent.futures
import subprocess
from datetime import datetime

# Termux color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class SimpleFinderTermux:
    def __init__(self, domain, wordlist=None, threads=15, timeout=15, 
                 output_format='txt', verbose=False):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output_format = output_format
        self.verbose = verbose
        self.found_subdomains = set()
        
        # Setup session for Termux
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36',
            'Accept': '*/*',
        })
        
        # Disable SSL verification for Termux
        self.session.verify = False
        
        # Check if nslookup is available
        self.use_nslookup = self.check_nslookup()
        
        # Create directories
        os.makedirs('results', exist_ok=True)
        os.makedirs('wordlists', exist_ok=True)

    def check_nslookup(self):
        """Check if nslookup is available in Termux"""
        try:
            result = subprocess.run(['nslookup', 'google.com'], 
                                   capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def display_banner(self):
        """Display SimpleFinder banner for Termux"""
        banner = f"""
{Colors.CYAN}{'═'*60}
{Colors.YELLOW}
    ╔═══╗╔╗ ╔╗╔═══╗╔═══╗╔╗╔═══╗╔═══╗╔═══╗╔╗╔═══╗╔════╗
    ║╔══╝║║ ║║║╔══╝║╔══╝║║║╔══╝║╔══╝║╔══╝║║║╔══╝║╔╗╔╗║
    ║╚══╗║║ ║║║╚══╗║╚══╗║║║╚══╗║╚══╗║╚══╗║║║╚══╗╚╝║║╚╝
    ║╔══╝║║ ║║║╔══╝║╔══╝║║║╔══╝║╔══╝║╔══╝║║║╔══╝  ║║  
    ║╚══╗║╚═╝║║╚══╗║╚══╗║╚╝║╔══╝║╔══╝║╚══╗║╚╝║╔══╗ ║║  
    ╚═══╝╚═══╝╚═══╝╚═══╝╚══╝╚═══╝╚═══╝╚═══╝╚══╝╚═══╝ ╚╝  
{Colors.GREEN}
    ╔══════════════════════════════════════════════╗
    ║         SIMPLEFINDER - TERMUX EDITION        ║
    ║                 Version 1.0.0                ║
    ║            Author: Cyber-Specterz            ║
    ╚══════════════════════════════════════════════╝
{Colors.CYAN}{'═'*60}{Colors.RESET}
"""
        print(banner)
        
        print(f"{Colors.CYAN}[*] Target Domain:{Colors.RESET} {Colors.YELLOW}{self.domain}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads:{Colors.RESET} {self.threads}")
        print(f"{Colors.CYAN}[*] Timeout:{Colors.RESET} {self.timeout}s")
        print(f"{Colors.CYAN}[*] Mode:{Colors.RESET} {Colors.GREEN}Termux (Android){Colors.RESET}")
        print(f"{Colors.CYAN}[*] Started:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.CYAN}{'─'*60}{Colors.RESET}\n")

    def dns_resolve_termux(self, subdomain):
        """DNS resolution optimized for Termux"""
        # Method 1: Try socket (fastest for Termux)
        try:
            ip = socket.gethostbyname(subdomain)
            return subdomain, [ip], 'A'
        except socket.gaierror:
            # Method 2: Try nslookup if available
            if self.use_nslookup:
                try:
                    result = subprocess.run(
                        ['nslookup', subdomain, '8.8.8.8'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if 'Address:' in result.stdout:
                        lines = result.stdout.split('\n')
                        ips = []
                        for line in lines:
                            if 'Address:' in line and '8.8.8.8' not in line:
                                ip = line.split(':')[1].strip()
                                if ip and ip != '8.8.8.8':
                                    ips.append(ip)
                        if ips:
                            return subdomain, ips, 'NSLOOKUP'
                except:
                    pass
        
        return None, [], 'Not Found'

    def query_api_simple(self, url, api_name):
        """Simple API query for Termux"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[-] {api_name} Error: {str(e)[:30]}{Colors.RESET}")
        return None

    def crtsh_lookup_termux(self):
        """crt.sh lookup for Termux"""
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            response = self.query_api_simple(url, "crt.sh")
            if response:
                try:
                    data = response.json()
                    subdomains = set()
                    for entry in data:
                        for field in ['name_value', 'common_name']:
                            if field in entry:
                                value = str(entry[field]).lower()
                                if self.domain in value:
                                    parts = value.split('\n')
                                    for part in parts:
                                        part = part.strip()
                                        if part.endswith(self.domain) and part != self.domain:
                                            if part.startswith('*.'):
                                                part = part[2:]
                                            subdomains.add(part)
                    if subdomains:
                        print(f"{Colors.GREEN}[+] crt.sh:{Colors.RESET} Found {len(subdomains)}")
                    return subdomains
                except:
                    # Fallback to regex parsing
                    subdomains = set()
                    pattern = r'[\w\.-]+\.' + re.escape(self.domain)
                    matches = re.findall(pattern, response.text.lower())
                    subdomains.update([m for m in matches if m != self.domain])
                    if subdomains:
                        print(f"{Colors.GREEN}[+] crt.sh:{Colors.RESET} Found {len(subdomains)} (regex)")
                    return subdomains
        except Exception:
            pass
        return set()

    def hackertarget_lookup_termux(self):
        """Hackertarget lookup for Termux"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.query_api_simple(url, "Hackertarget")
            if response and "error" not in response.text.lower():
                subdomains = set()
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.domain}"):
                            subdomains.add(subdomain)
                if subdomains:
                    print(f"{Colors.GREEN}[+] Hackertarget:{Colors.RESET} Found {len(subdomains)}")
                return subdomains
        except Exception:
            pass
        return set()

    def brute_force_termux(self):
        """Brute force optimized for Termux"""
        # Built-in wordlist for Termux
        builtin_words = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog',
            'shop', 'app', 'mobile', 'web', 'secure', 'portal', 'vpn',
            'cdn', 'static', 'assets', 'media', 'download', 'upload',
            'cpanel', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'dns',
            'mx', 'mail1', 'mail2', 'webdisk', 'whm', 'server', 'server1',
            'server2', 'cluster', 'cluster1', 'cluster2', 'node', 'node1',
            'node2', 'db', 'database', 'mysql', 'mongo', 'redis', 'cache',
            'git', 'svn', 'repo', 'docker', 'k8s', 'kubernetes', 'jenkins',
            'ci', 'cd', 'stage', 'staging', 'prod', 'production', 'beta',
            'alpha', 'demo', 'test1', 'test2', 'uat', 'preprod', 'sandbox'
        ]
        
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, 'r') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                words = list(set(builtin_words + custom_words))[:150]
            except:
                words = builtin_words[:80]
        else:
            words = builtin_words[:80]
        
        subdomains = set()
        found_count = 0
        total_words = len(words)
        
        print(f"{Colors.CYAN}[*] Brute forcing with {total_words} words...{Colors.RESET}")
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for word in words:
                    subdomain = f"{word}.{self.domain}"
                    futures.append(executor.submit(self.dns_resolve_termux, subdomain))
                
                for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    result = future.result()
                    if result[0]:
                        found_subdomain, records, record_type = result
                        subdomains.add(found_subdomain)
                        found_count += 1
                        if self.verbose:
                            print(f"{Colors.GREEN}[+] {found_subdomain}{Colors.RESET}")
                    
                    # Progress update
                    if i % 20 == 0 or i == total_words:
                        print(f"{Colors.CYAN}[*] Progress: {i}/{total_words} | Found: {found_count}{Colors.RESET}")
            
            if subdomains:
                print(f"{Colors.GREEN}[+] Brute Force:{Colors.RESET} Found {len(subdomains)}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Brute force error: {str(e)[:30]}{Colors.RESET}")
        
        return subdomains

    def save_results(self, subdomains):
        """Save results to file"""
        if not subdomains:
            print(f"{Colors.YELLOW}[!] No subdomains found{Colors.RESET}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"simplefinder_{self.domain}_{timestamp}"
        
        # Save to text file
        txt_filename = f"results/{base_filename}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"# SimpleFinder Results - Termux Edition\n")
            f.write(f"# Domain: {self.domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Found: {len(subdomains)}\n")
            f.write("#" * 60 + "\n\n")
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        print(f"\n{Colors.GREEN}[+] Results saved:{Colors.RESET}")
        print(f"   {Colors.CYAN}📄 Text:{Colors.RESET} {txt_filename}")
        
        # Show how to access from Android
        print(f"\n{Colors.YELLOW}[*] To access from Android:{Colors.RESET}")
        print(f"   cp {txt_filename} ~/storage/shared/Download/")

    def run(self):
        """Main execution method"""
        self.display_banner()
        
        all_subdomains = set()
        start_time = time.time()
        
        print(f"{Colors.YELLOW}[*] Starting enumeration...{Colors.RESET}\n")
        
        # API-based enumeration
        apis = [
            (self.crtsh_lookup_termux, "Certificate Transparency"),
            (self.hackertarget_lookup_termux, "Hackertarget API"),
        ]
        
        for api_func, api_name in apis:
            print(f"{Colors.CYAN}[*] Querying {api_name}...{Colors.RESET}")
            try:
                subdomains = api_func()
                new_subdomains = subdomains - all_subdomains
                all_subdomains.update(new_subdomains)
                time.sleep(1)  # Rate limiting for Termux
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}   [!] Error: {str(e)[:30]}{Colors.RESET}")
        
        # DNS brute force
        print(f"{Colors.CYAN}[*] Starting DNS brute force...{Colors.RESET}")
        brute_subdomains = self.brute_force_termux()
        new_subdomains = brute_subdomains - all_subdomains
        all_subdomains.update(new_subdomains)
        
        elapsed_time = time.time() - start_time
        
        # Display summary
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] SCAN COMPLETED{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
        print(f"{Colors.YELLOW}Target Domain:{Colors.RESET} {self.domain}")
        print(f"{Colors.YELLOW}Total Subdomains Found:{Colors.RESET} {len(all_subdomains)}")
        print(f"{Colors.YELLOW}Scan Duration:{Colors.RESET} {elapsed_time:.2f} seconds")
        if elapsed_time > 0 and len(all_subdomains) > 0:
            print(f"{Colors.YELLOW}Scan Rate:{Colors.RESET} {len(all_subdomains)/elapsed_time:.2f} subdomains/sec")
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
        
        # Display found subdomains
        if all_subdomains:
            print(f"\n{Colors.CYAN}[*] Found Subdomains:{Colors.RESET}")
            for i, subdomain in enumerate(sorted(all_subdomains), 1):
                if i <= 30:
                    print(f"  {i:3}. {subdomain}")
                else:
                    remaining = len(all_subdomains) - 30
                    print(f"  {Colors.YELLOW}... and {remaining} more (see results file){Colors.RESET}")
                    break
        
        # Save results
        self.save_results(all_subdomains)
        
        return all_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='SimpleFinder - Subdomain Scanner for Termux by Cyber-Specterz',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.GREEN}Examples:{Colors.RESET}
  python simplefinder-termux.py instagram.com
  python simplefinder-termux.py google.com -t 15 -v
  
{Colors.YELLOW}Termux Tips:{Colors.RESET}
  • Use 10-15 threads for best performance
  • Results saved in results/ folder
  • Copy to Android: cp results/*.txt ~/storage/shared/Download/
  • Use WiFi for faster scans
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., instagram.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', default=None)
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds (default: 15)')
    parser.add_argument('-o', '--output', choices=['txt'], default='txt', help='Output format (default: txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Colors.RED}[!] Please provide a domain{Colors.RESET}")
        print(f"Example: python {sys.argv[0]} instagram.com")
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Validate domain
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
        print(f"{Colors.RED}[!] Invalid domain format{Colors.RESET}")
        sys.exit(1)
    
    # Create scanner
    scanner = SimpleFinderTermux(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output_format=args.output,
        verbose=args.verbose
    )
    
    try:
        results = scanner.run()
        if not results:
            print(f"\n{Colors.YELLOW}[!] No subdomains found for {args.domain}{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    print(f"{Colors.GREEN}[*] SimpleFinder Termux Edition v1.0.0 by Cyber-Specterz{Colors.RESET}")
    main()
EOF

# Make the script executable
chmod +x simplefinder-termux.py

# Create alias for easy access
echo "alias simplefinder='cd ~/simplefinder && python simplefinder-termux.py'" >> ~/.bashrc

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Installation Complete!               ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  cd ~/simplefinder"
echo "  python simplefinder-termux.py instagram.com"
echo ""
echo -e "${YELLOW}Or use alias:${NC}"
echo "  simplefinder google.com"
echo ""
echo -e "${YELLOW}Access Results:${NC}"
echo "  cp results/*.txt ~/storage/shared/Download/"
echo ""