#!/data/data/com.termux/files/usr/bin/python3
"""
SimpleFinderz - Termux Optimized Subdomain Scanner
Author: Cyber-Specterz
Version: 2.0.3 (Termux Fixed Edition)
"""

import sys
import os
import argparse
import requests
import json
import time
import dns.resolver
import socket
import ssl
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
import warnings
import urllib3

# Disable SSL warnings for Termux
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Termux-specific fixes
if 'com.termux' in os.getcwd() or 'TERMUX' in os.environ:
    # Fix SSL context for Termux
    ssl._create_default_https_context = ssl._create_unverified_context
    # Create resolv.conf for Termux
    termux_resolv = '/data/data/com.termux/files/usr/etc/resolv.conf'
    os.makedirs(os.path.dirname(termux_resolv), exist_ok=True)
    with open(termux_resolv, 'w') as f:
        f.write("nameserver 8.8.8.8\n")
        f.write("nameserver 1.1.1.1\n")
        f.write("nameserver 8.8.4.4\n")
    os.environ['RESOLV_CONF'] = termux_resolv

# User agents for requests
USER_AGENTS = [
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'SimpleFinderz/2.0.3 (Termux)'
]

class TermuxColors:
    """Color class for Termux compatibility"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def print(color, text):
        print(f"{color}{text}{TermuxColors.RESET}")

class SimpleFinderz:
    def __init__(self, domain, wordlist=None, threads=20, timeout=15, 
                 output_format='txt', verbose=False, use_dns=True, 
                 use_apis=True, use_wordlist=True):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output_format = output_format
        self.verbose = verbose
        self.use_dns = use_dns
        self.use_apis = use_apis
        self.use_wordlist = use_wordlist
        self.found_subdomains = set()
        self.active_subdomains = set()
        
        # Setup session with Termux optimizations
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for Termux
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        
        # Setup DNS resolver for Termux - FIXED VERSION
        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
            # Manually set nameservers for Termux
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
            # Disable reading from /etc/resolv.conf
            self.resolver._resolv_conf = None
        except Exception as e:
            print(f"{TermuxColors.YELLOW}[!] DNS resolver warning: {e}{TermuxColors.RESET}")
            # Fallback to socket DNS
            self.resolver = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create results directory
        os.makedirs('results', exist_ok=True)

    def display_banner(self):
        """Display SimpleFinderz banner optimized for Termux"""
        banner = f"""
{TermuxColors.CYAN}{'═'*60}
{TermuxColors.YELLOW}
        ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗
        ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝
        ███████╗██║██╔████╔██║██████╔╝██║     █████╗ 
        ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝  
        ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗
        ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝
{TermuxColors.GREEN}
╔══════════════════════════════════════════╗
║    SimpleFinderz - Termux Edition        ║
║        Version 2.0.3                     ║
║        Author: Cyber-Specterz            ║
╚══════════════════════════════════════════╝
{TermuxColors.CYAN}{'═'*60}{TermuxColors.RESET}
"""
        print(banner)
        
        print(f"{TermuxColors.CYAN}[*] Target Domain:{TermuxColors.RESET} {TermuxColors.YELLOW}{self.domain}{TermuxColors.RESET}")
        print(f"{TermuxColors.CYAN}[*] Threads:{TermuxColors.RESET} {self.threads}")
        print(f"{TermuxColors.CYAN}[*] Timeout:{TermuxColors.RESET} {self.timeout}s")
        print(f"{TermuxColors.CYAN}[*] Mode:{TermuxColors.RESET} {'Termux' if 'com.termux' in os.getcwd() else 'Desktop'}")
        print(f"{TermuxColors.CYAN}[*] Started:{TermuxColors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{TermuxColors.CYAN}{'─'*60}{TermuxColors.RESET}\n")

    def dns_resolve_simple(self, subdomain):
        """Simple DNS resolution without dnspython - works in Termux"""
        try:
            # Method 1: Try socket (most reliable in Termux)
            ip = socket.gethostbyname(subdomain)
            return subdomain, [ip], 'A'
        except socket.gaierror:
            # Method 2: Try using requests to public DNS
            try:
                import subprocess
                result = subprocess.run(['nslookup', subdomain, '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=5)
                if 'Address:' in result.stdout:
                    lines = result.stdout.split('\n')
                    ips = []
                    for line in lines:
                        if 'Address:' in line and not '#' in line:
                            ip = line.split(':')[1].strip()
                            if ip != '8.8.8.8':
                                ips.append(ip)
                    if ips:
                        return subdomain, ips, 'NSLOOKUP'
            except:
                pass
        
        return None, [], 'Not Found'

    def dns_resolve(self, subdomain):
        """DNS resolution with fallback for Termux"""
        if self.resolver:
            try:
                # Try A record with dnspython
                answers = self.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                return subdomain, ips, 'A'
            except dns.resolver.NXDOMAIN:
                return None, [], 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                try:
                    # Try CNAME
                    answers = self.resolver.resolve(subdomain, 'CNAME')
                    cnames = [str(rdata.target).rstrip('.') for rdata in answers]
                    return subdomain, cnames, 'CNAME'
                except:
                    return None, [], 'NoAnswer'
            except Exception:
                # Fallback to simple resolution
                return self.dns_resolve_simple(subdomain)
        else:
            # Use simple resolution
            return self.dns_resolve_simple(subdomain)

    def crtsh_lookup(self):
        """Query crt.sh for subdomains - Termux optimized"""
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    for entry in data:
                        # Extract from common_name and name_value
                        for field in ['common_name', 'name_value']:
                            if field in entry and entry[field]:
                                names = str(entry[field]).split('\n')
                                for name in names:
                                    name = name.strip().lower().replace('*.', '')
                                    if name.endswith(self.domain) and name != self.domain:
                                        # Clean and add
                                        if name.startswith('*.'):
                                            name = name[2:]
                                        if '.' + self.domain in name:
                                            subdomains.add(name)
                    
                    if subdomains:
                        TermuxColors.print(TermuxColors.GREEN, f"[+] crt.sh: {len(subdomains)} subdomains")
                    return subdomains
                    
                except json.JSONDecodeError:
                    # Fallback: regex search
                    subdomains = set()
                    pattern = r'[\w\.-]+\.' + re.escape(self.domain)
                    matches = re.findall(pattern, response.text.lower())
                    subdomains.update([m for m in matches if m != self.domain])
                    if subdomains:
                        TermuxColors.print(TermuxColors.GREEN, f"[+] crt.sh: {len(subdomains)} subdomains (regex)")
                    return subdomains
            else:
                if self.verbose:
                    TermuxColors.print(TermuxColors.YELLOW, f"[-] crt.sh: HTTP {response.status_code}")
                    
        except Exception as e:
            if self.verbose:
                TermuxColors.print(TermuxColors.RED, f"[!] crt.sh: {str(e)[:50]}")
        return set()

    def hackertarget_lookup(self):
        """Query hackertarget.com - Free API for Termux"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and "error" not in response.text.lower():
                subdomains = set()
                for line in response.text.split('\n'):
                    if line and ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
                            subdomains.add(subdomain)
                
                if subdomains:
                    TermuxColors.print(TermuxColors.GREEN, f"[+] Hackertarget: {len(subdomains)} subdomains")
                return subdomains
                
        except Exception as e:
            if self.verbose:
                TermuxColors.print(TermuxColors.RED, f"[!] Hackertarget: {str(e)[:50]}")
        return set()

    def anubis_lookup(self):
        """Query Anubis API"""
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = {sub.lower() for sub in data if sub.endswith(f".{self.domain}") and sub != self.domain}
                    if subdomains:
                        TermuxColors.print(TermuxColors.GREEN, f"[+] Anubis: {len(subdomains)} subdomains")
                    return subdomains
                except:
                    pass
        except:
            pass
        return set()

    def brute_force_subdomains(self):
        """Brute force with built-in wordlist for Termux"""
        # Built-in wordlist optimized for mobile
        builtin_words = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 
            'shop', 'app', 'mobile', 'm', 'cpanel', 'webmail', 'smtp',
            'pop', 'ns1', 'ns2', 'web', 'secure', 'portal', 'vpn', 'wiki',
            'demo', 'stage', 'staging', 'beta', 'alpha', 'prod', 'production',
            'cdn', 'static', 'assets', 'media', 'img', 'images', 'js', 'css',
            'download', 'upload', 'files', 'video', 'audio', 'chat', 'support',
            'help', 'docs', 'documentation', 'status', 'monitor', 'stats',
            'analytics', 'track', 'tracking', 'ads', 'ad', 'adserver',
            'banner', 'affiliate', 'partner', 'affiliates', 'partners',
            'reseller', 'resellers', 'client', 'clients', 'customer',
            'customers', 'user', 'users', 'member', 'members', 'account',
            'accounts', 'billing', 'invoice', 'payment', 'pay', 'checkout',
            'store', 'shop', 'cart', 'market', 'marketplace', 'buy', 'sell',
            'trade', 'trading', 'exchange', 'wallet', 'bank', 'banking',
            'finance', 'financial', 'money', 'cash', 'credit', 'debit',
            'card', 'cards', 'insurance', 'insure', 'assurance', 'assure',
            'trust', 'trusted', 'secure', 'security', 'safe', 'safety',
            'protect', 'protection', 'guard', 'guarding', 'shield', 'shielding',
            'defense', 'defence', 'defend', 'defending', 'attack', 'attacking',
            'hack', 'hacking', 'hacker', 'hackers', 'crack', 'cracking',
            'cracker', 'crackers', 'exploit', 'exploiting', 'exploiter'
        ]
        
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, 'r') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                words = list(set(builtin_words + custom_words))
            except:
                words = builtin_words
        else:
            words = builtin_words[:100]  # Use first 100 for speed
        
        subdomains = set()
        found_count = 0
        total_words = len(words)
        
        TermuxColors.print(TermuxColors.CYAN, f"[*] Brute forcing with {total_words} words...")
        
        try:
            with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as executor:
                futures = []
                for i, word in enumerate(words):
                    subdomain = f"{word}.{self.domain}"
                    futures.append(executor.submit(self.dns_resolve, subdomain))
                
                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        result = future.result(timeout=10)
                        if result and result[0]:  # Subdomain found
                            found_subdomain, records, record_type = result
                            subdomains.add(found_subdomain)
                            found_count += 1
                            if self.verbose:
                                rec_str = ', '.join(records[:2])
                                if len(records) > 2:
                                    rec_str += '...'
                                TermuxColors.print(TermuxColors.GREEN, f"[+] {found_subdomain}")
                    except Exception:
                        pass
                    
                    # Progress update
                    if i % 20 == 0 or i == total_words:
                        print(f"{TermuxColors.CYAN}[*] Progress: {i}/{total_words} | Found: {found_count}{TermuxColors.RESET}")
            
            if subdomains:
                TermuxColors.print(TermuxColors.GREEN, f"[+] Brute force: {len(subdomains)} subdomains")
            
        except Exception as e:
            TermuxColors.print(TermuxColors.RED, f"[!] Brute force error: {str(e)[:50]}")
        
        return subdomains

    def save_results(self, subdomains):
        """Save results to file"""
        if not subdomains:
            TermuxColors.print(TermuxColors.YELLOW, "[!] No subdomains found")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"simplefinderz_{self.domain}_{timestamp}"
        
        # Save to text file
        txt_filename = f"results/{base_filename}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"# SimpleFinderz Results - Termux Edition\n")
            f.write(f"# Domain: {self.domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Found: {len(subdomains)}\n")
            f.write("#" * 60 + "\n\n")
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        # Save to JSON if requested
        if self.output_format in ['json', 'both']:
            json_filename = f"results/{base_filename}.json"
            results = {
                'domain': self.domain,
                'scan_date': datetime.now().isoformat(),
                'total_subdomains': len(subdomains),
                'subdomains': sorted(list(subdomains))
            }
            with open(json_filename, 'w') as f:
                json.dump(results, f, indent=2)
        
        TermuxColors.print(TermuxColors.GREEN, f"\n[+] Results saved:")
        TermuxColors.print(TermuxColors.CYAN, f"   📄 Text: {txt_filename}")
        if self.output_format in ['json', 'both']:
            TermuxColors.print(TermuxColors.CYAN, f"   📊 JSON: {json_filename}")

    def run(self):
        """Main execution method"""
        self.display_banner()
        
        all_subdomains = set()
        start_time = time.time()
        
        TermuxColors.print(TermuxColors.YELLOW, "[*] Starting enumeration...\n")
        
        # API-based enumeration
        if self.use_apis:
            methods = [
                (self.crtsh_lookup, "Certificate Transparency"),
                (self.hackertarget_lookup, "Hackertarget API"),
                (self.anubis_lookup, "Anubis Database"),
            ]
            
            for method, name in methods:
                TermuxColors.print(TermuxColors.CYAN, f"[*] Querying {name}...")
                try:
                    subdomains = method()
                    new_subdomains = subdomains - all_subdomains
                    all_subdomains.update(new_subdomains)
                    time.sleep(0.5)  # Rate limiting
                except Exception as e:
                    if self.verbose:
                        TermuxColors.print(TermuxColors.YELLOW, f"   [!] {str(e)[:50]}")
        
        # DNS brute force
        if self.use_dns and self.use_wordlist:
            TermuxColors.print(TermuxColors.CYAN, f"\n[*] Starting DNS brute force...")
            brute_subdomains = self.brute_force_subdomains()
            new_subdomains = brute_subdomains - all_subdomains
            all_subdomains.update(new_subdomains)
        
        elapsed_time = time.time() - start_time
        
        # Display summary
        print(f"\n{TermuxColors.CYAN}{'═'*60}{TermuxColors.RESET}")
        TermuxColors.print(TermuxColors.GREEN, "[✓] SCAN COMPLETED")
        print(f"{TermuxColors.CYAN}{'═'*60}{TermuxColors.RESET}")
        print(f"{TermuxColors.YELLOW}Target Domain:{TermuxColors.RESET} {self.domain}")
        print(f"{TermuxColors.YELLOW}Total Subdomains Found:{TermuxColors.RESET} {len(all_subdomains)}")
        print(f"{TermuxColors.YELLOW}Scan Duration:{TermuxColors.RESET} {elapsed_time:.2f} seconds")
        if elapsed_time > 0 and len(all_subdomains) > 0:
            print(f"{TermuxColors.YELLOW}Scan Rate:{TermuxColors.RESET} {len(all_subdomains)/elapsed_time:.2f} subdomains/sec")
        print(f"{TermuxColors.CYAN}{'═'*60}{TermuxColors.RESET}")
        
        # Display found subdomains
        if all_subdomains:
            TermuxColors.print(TermuxColors.CYAN, f"\n[*] Found Subdomains:")
            for i, subdomain in enumerate(sorted(all_subdomains), 1):
                if i <= 30:  # Show first 30 only
                    print(f"  {i:3}. {subdomain}")
                else:
                    remaining = len(all_subdomains) - 30
                    TermuxColors.print(TermuxColors.YELLOW, f"  ... and {remaining} more (see results file)")
                    break
        
        # Save results
        self.save_results(all_subdomains)
        
        return all_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='SimpleFinderz - Subdomain Scanner (Termux Edition)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simplefinderz.py instagram.com
  python simplefinderz.py google.com -t 15 -v
  python simplefinderz.py example.com --no-api
  
Termux Tips:
  • Results saved in: results/ folder
  • Use -t 15 for stable performance
  • Add -v for detailed output
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., instagram.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', default=None)
    parser.add_argument('-t', '--threads', type=int, default=15, help='Threads (default: 15)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout seconds (default: 10)')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'both'], default='txt', help='Output format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-api', action='store_true', help='Disable API queries')
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS brute force')
    
    # Check if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{TermuxColors.RED}[!] Please provide a domain{TermuxColors.RESET}")
        print(f"Example: python {sys.argv[0]} instagram.com")
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Check if domain is valid
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
        TermuxColors.print(TermuxColors.RED, "[!] Invalid domain")
        print(f"    Example: instagram.com, google.com")
        sys.exit(1)
    
    # Create scanner instance
    scanner = SimpleFinderz(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output_format=args.output,
        verbose=args.verbose,
        use_dns=not args.no_dns,
        use_apis=not args.no_api,
        use_wordlist=True
    )
    
    try:
        results = scanner.run()
        if not results:
            TermuxColors.print(TermuxColors.YELLOW, f"\n[!] No subdomains found for {args.domain}")
            TermuxColors.print(TermuxColors.CYAN, "[*] Try: python simplefinderz.py google.com -v")
    except KeyboardInterrupt:
        TermuxColors.print(TermuxColors.YELLOW, "\n[!] Scan interrupted")
        sys.exit(0)
    except Exception as e:
        TermuxColors.print(TermuxColors.RED, f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Termux detection and setup
    is_termux = 'com.termux' in os.getcwd() or 'TERMUX' in os.environ
    
    if is_termux:
        print(f"{TermuxColors.GREEN}[*] Running in Termux{TermuxColors.RESET}")
        print(f"{TermuxColors.CYAN}[*] DNS resolver configured{TermuxColors.RESET}")
    else:
        print(f"{TermuxColors.BLUE}[*] Running in desktop mode{TermuxColors.RESET}")
    
    main()
