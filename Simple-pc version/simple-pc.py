#!/usr/bin/env python3
"""
SimpleFinderz - Professional Subdomain Scanner (PC Edition)
Author: Cyber-Specterz
Version: 3.0.0 PC
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
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

class Colors:
    """Console colors for PC"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class SimpleFinderzPC:
    def __init__(self, domain, wordlist=None, threads=50, timeout=10, 
                 output_format='txt', verbose=False, use_dns=True, 
                 use_apis=True, use_wordlist=True, use_all=True):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output_format = output_format
        self.verbose = verbose
        self.use_dns = use_dns
        self.use_apis = use_apis
        self.use_wordlist = use_wordlist
        self.use_all = use_all
        self.found_subdomains = set()
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        # Setup DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create directories
        os.makedirs('results', exist_ok=True)
        os.makedirs('wordlists', exist_ok=True)

    def display_banner(self):
        """Display banner for PC"""
        banner = f"""
{Colors.CYAN}{'═'*70}
{Colors.YELLOW}
        ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗
        ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝
        ███████╗██║██╔████╔██║██████╔╝██║     █████╗ 
        ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝  
        ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗
        ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝
{Colors.GREEN}
    ╔══════════════════════════════════════════════════╗
    ║           SIMPLEFINDERZ - PC EDITION             ║
    ║                Version 2.0.0                     ║
    ║             Author: Cyber-Specterz               ║
    ╚══════════════════════════════════════════════════╝
{Colors.CYAN}{'═'*70}{Colors.RESET}
"""
        print(banner)
        
        print(f"{Colors.CYAN}[*] Target Domain:{Colors.RESET} {Colors.YELLOW}{self.domain}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Threads:{Colors.RESET} {self.threads}")
        print(f"{Colors.CYAN}[*] Timeout:{Colors.RESET} {self.timeout}s")
        print(f"{Colors.CYAN}[*] Mode:{Colors.RESET} {Colors.GREEN}PC (Full Power){Colors.RESET}")
        print(f"{Colors.CYAN}[*] Started:{Colors.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}\n")

    def query_api(self, url, api_name):
        """Query any API"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[-] {api_name} API Error: {str(e)[:50]}{Colors.RESET}")
        return None

    def crtsh_lookup(self):
        """Query crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.query_api(url, "crt.sh")
            if response:
                data = response.json()
                subdomains = set()
                for entry in data:
                    for field in ['name_value', 'common_name']:
                        if field in entry:
                            values = str(entry[field]).split('\n')
                            for value in values:
                                value = value.strip().lower()
                                if value.endswith(self.domain) and value != self.domain:
                                    if value.startswith('*.'):
                                        value = value[2:]
                                    subdomains.add(value)
                if subdomains:
                    print(f"{Colors.GREEN}[+] crt.sh:{Colors.RESET} Found {len(subdomains)} subdomains")
                return subdomains
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[-] crt.sh Error: {str(e)[:50]}{Colors.RESET}")
        return set()

    def hackertarget_lookup(self):
        """Query Hackertarget"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.query_api(url, "Hackertarget")
            if response and "error" not in response.text.lower():
                subdomains = set()
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.domain}"):
                            subdomains.add(subdomain)
                if subdomains:
                    print(f"{Colors.GREEN}[+] Hackertarget:{Colors.RESET} Found {len(subdomains)} subdomains")
                return subdomains
        except Exception:
            pass
        return set()

    def threatcrowd_lookup(self):
        """Query ThreatCrowd"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.query_api(url, "ThreatCrowd")
            if response:
                data = response.json()
                if 'subdomains' in data:
                    subdomains = {sub.lower() for sub in data['subdomains'] if sub.endswith(f".{self.domain}")}
                    if subdomains:
                        print(f"{Colors.GREEN}[+] ThreatCrowd:{Colors.RESET} Found {len(subdomains)} subdomains")
                    return subdomains
        except Exception:
            pass
        return set()

    def bufferover_lookup(self):
        """Query BufferOver.run"""
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            response = self.query_api(url, "BufferOver")
            if response:
                data = response.json()
                subdomains = set()
                if 'FDNS_A' in data:
                    for entry in data['FDNS_A']:
                        parts = entry.split(',')
                        if len(parts) > 1:
                            subdomain = parts[1].strip().lower()
                            if subdomain.endswith(f".{self.domain}"):
                                subdomains.add(subdomain)
                if subdomains:
                    print(f"{Colors.GREEN}[+] BufferOver:{Colors.RESET} Found {len(subdomains)} subdomains")
                return subdomains
        except Exception:
            pass
        return set()

    def dns_resolve(self, subdomain):
        """DNS resolution for PC"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            return subdomain, ips, 'A'
        except dns.resolver.NXDOMAIN:
            return None, [], 'NXDOMAIN'
        except dns.resolver.NoAnswer:
            try:
                answers = self.resolver.resolve(subdomain, 'CNAME')
                cnames = [str(rdata.target).rstrip('.') for rdata in answers]
                return subdomain, cnames, 'CNAME'
            except:
                return None, [], 'NoAnswer'
        except Exception:
            return None, [], 'Error'

    def brute_force_subdomains(self):
        """Brute force subdomains"""
        # Load wordlist
        words = []
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
            except:
                pass
        
        # Use default wordlist if empty
        if not words:
            default_words = [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 'shop',
                'app', 'mobile', 'm', 'cpanel', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'web', 'secure', 'portal', 'vpn', 'wiki', 'demo', 'stage', 'staging',
                'beta', 'alpha', 'prod', 'production', 'cdn', 'static', 'assets',
                'media', 'img', 'images', 'js', 'css', 'download', 'upload', 'files'
            ]
            words = default_words
        
        subdomains = set()
        found_count = 0
        total_words = len(words)
        
        print(f"{Colors.CYAN}[*] Brute forcing with {total_words} words...{Colors.RESET}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for word in words:
                    subdomain = f"{word}.{self.domain}"
                    futures.append(executor.submit(self.dns_resolve, subdomain))
                
                for i, future in enumerate(as_completed(futures), 1):
                    result = future.result()
                    if result[0]:
                        found_subdomain, records, record_type = result
                        subdomains.add(found_subdomain)
                        found_count += 1
                        if self.verbose:
                            rec_str = ', '.join(records[:2])
                            if len(records) > 2:
                                rec_str += '...'
                            print(f"{Colors.GREEN}[+] {found_subdomain}{Colors.RESET}")
                    
                    # Progress update
                    if i % 100 == 0 or i == total_words:
                        print(f"{Colors.CYAN}[*] Progress: {i}/{total_words} | Found: {found_count}{Colors.RESET}")
            
            if subdomains:
                print(f"{Colors.GREEN}[+] Brute Force:{Colors.RESET} Found {len(subdomains)} subdomains")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Brute force error: {str(e)[:50]}{Colors.RESET}")
        
        return subdomains

    def save_results(self, subdomains):
        """Save results to file"""
        if not subdomains:
            print(f"{Colors.YELLOW}[!] No subdomains found to save{Colors.RESET}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"simplefinderz_{self.domain}_{timestamp}"
        
        # Save to text file
        txt_filename = f"results/{base_filename}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"# SimpleFinderz Results - PC Edition\n")
            f.write(f"# Domain: {self.domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Found: {len(subdomains)}\n")
            f.write("#" * 70 + "\n\n")
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
        
        print(f"\n{Colors.GREEN}[+] Results saved:{Colors.RESET}")
        print(f"   {Colors.CYAN}📄 Text:{Colors.RESET} {txt_filename}")
        if self.output_format in ['json', 'both']:
            print(f"   {Colors.CYAN}📊 JSON:{Colors.RESET} {json_filename}")

    def run(self):
        """Main execution method"""
        self.display_banner()
        
        all_subdomains = set()
        start_time = time.time()
        
        print(f"{Colors.YELLOW}[*] Starting enumeration...{Colors.RESET}\n")
        
        # API-based enumeration
        if self.use_apis:
            apis = [
                (self.crtsh_lookup, "Certificate Transparency"),
                (self.hackertarget_lookup, "Hackertarget API"),
                (self.threatcrowd_lookup, "ThreatCrowd"),
                (self.bufferover_lookup, "BufferOver DNS"),
            ]
            
            for api_func, api_name in apis:
                print(f"{Colors.CYAN}[*] Querying {api_name}...{Colors.RESET}")
                try:
                    subdomains = api_func()
                    new_subdomains = subdomains - all_subdomains
                    all_subdomains.update(new_subdomains)
                    time.sleep(0.3)  # Rate limiting
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}   [!] Error: {str(e)[:50]}{Colors.RESET}")
        
        # DNS brute force
        if self.use_dns and self.use_wordlist:
            print(f"{Colors.CYAN}[*] Starting DNS brute force...{Colors.RESET}")
            brute_subdomains = self.brute_force_subdomains()
            new_subdomains = brute_subdomains - all_subdomains
            all_subdomains.update(new_subdomains)
        
        elapsed_time = time.time() - start_time
        
        # Display summary
        print(f"\n{Colors.CYAN}{'═'*70}{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] SCAN COMPLETED{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}Target Domain:{Colors.RESET} {self.domain}")
        print(f"{Colors.YELLOW}Total Subdomains Found:{Colors.RESET} {len(all_subdomains)}")
        print(f"{Colors.YELLOW}Scan Duration:{Colors.RESET} {elapsed_time:.2f} seconds")
        if elapsed_time > 0 and len(all_subdomains) > 0:
            print(f"{Colors.YELLOW}Scan Rate:{Colors.RESET} {len(all_subdomains)/elapsed_time:.2f} subdomains/sec")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        
        # Display found subdomains
        if all_subdomains:
            print(f"\n{Colors.CYAN}[*] Found Subdomains:{Colors.RESET}")
            for i, subdomain in enumerate(sorted(all_subdomains), 1):
                if i <= 50:
                    print(f"  {i:3}. {subdomain}")
                else:
                    remaining = len(all_subdomains) - 50
                    print(f"  {Colors.YELLOW}... and {remaining} more (see results file){Colors.RESET}")
                    break
        
        # Save results
        self.save_results(all_subdomains)
        
        return all_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='SimpleFinderz - Professional Subdomain Scanner (PC Edition)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.GREEN}Examples:{Colors.RESET}
  python simplefinderz-pc.py instagram.com
  python simplefinderz-pc.py google.com -t 100 -v
  python simplefinderz-pc.py example.com -w wordlist.txt -o json
  
{Colors.YELLOW}PC Features:{Colors.RESET}
  • High-performance scanning (50+ threads)
  • Multiple API sources
  • Fast DNS resolution
  • JSON/TXT output formats
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., instagram.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', default=None)
    parser.add_argument('-t', '--threads', type=int, default=50, help='Threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout seconds (default: 10)')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'both'], default='txt', help='Output format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-api', action='store_true', help='Disable API queries')
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS brute force')
    
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
    scanner = SimpleFinderzPC(
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
            print(f"\n{Colors.YELLOW}[!] No subdomains found for {args.domain}{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print(f"{Colors.BLUE}[*] SimpleFinderz PC Edition v3.0.0{Colors.RESET}")
    main()