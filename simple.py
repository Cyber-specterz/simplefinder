#!/usr/bin/env python3
"""
SimpleFinderz - Advanced Subdomain Enumeration Tool
Author: Cyber-Psecterz
Version: 2.0.1
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
from urllib.parse import urlparse
from datetime import datetime
import logging
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# User agents for requests
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Load API keys from environment or config file
def load_api_keys():
    api_keys = {}
    try:
        # Try to load from environment variables first
        api_keys['virustotal'] = os.getenv('VIRUSTOTAL_API_KEY', '')
        api_keys['securitytrails'] = os.getenv('SECURITYTRAILS_API_KEY', '')
        api_keys['shodan'] = os.getenv('SHODAN_API_KEY', '')
        return api_keys
    except Exception:
        return {}

API_KEYS = load_api_keys()

class SimpleFinderz:
    def __init__(self, domain, wordlist=None, threads=50, timeout=10, 
                 output_format='txt', verbose=False, use_dns=True, 
                 use_apis=True, use_wordlist=True):
        self.domain = domain
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
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json'
        })
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def display_banner(self):
        """Display SimpleFinderz banner"""
        banner = f"""
{Fore.CYAN}{'═'*70}
{Fore.YELLOW}
        ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗███╗   ██╗██████╗ ███████╗██████╗ ███████╗
        ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
        ███████╗██║██╔████╔██║██████╔╝██║     █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝███████╗
        ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗╚════██║
        ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗██║ ╚████║██████╔╝███████╗██║  ██║███████║
        ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
{Fore.GREEN}
        ╔══════════════════════════════════════════════════════════════╗
        ║                  ADVANCED SUBDOMAIN SCANNER                  ║
        ║                         Version 2.0.1                        ║
        ║                     Author: Cyber-Psecterz                   ║
        ╚══════════════════════════════════════════════════════════════╝
{Fore.CYAN}{'═'*70}{Style.RESET_ALL}
"""
        print(banner)
        
        print(f"{Fore.CYAN}[*] Target Domain:{Style.RESET_ALL} {Fore.YELLOW}{self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads:{Style.RESET_ALL} {self.threads}")
        print(f"{Fore.CYAN}[*] Timeout:{Style.RESET_ALL} {self.timeout}s")
        print(f"{Fore.CYAN}[*] Output Format:{Style.RESET_ALL} {self.output_format}")
        print(f"{Fore.CYAN}[*] Started:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")

    def crtsh_lookup(self):
        """Query crt.sh for subdomains - FIXED"""
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    for entry in data:
                        # Extract subdomains from various fields
                        fields = ['name_value', 'common_name']
                        for field in fields:
                            if field in entry and entry[field]:
                                names = entry[field].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    # Clean the name
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    if name.endswith(f".{self.domain}"):
                                        subdomains.add(name)
                                    elif name == self.domain:
                                        subdomains.add(name)
                    self.logger.info(f"{Fore.GREEN}[+] crt.sh: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
                    return subdomains
                except json.JSONDecodeError:
                    # Try alternative parsing
                    subdomains = set()
                    for line in response.text.split('\n'):
                        if self.domain in line.lower():
                            # Extract possible subdomains
                            matches = re.findall(r'[\w\.-]+\.' + re.escape(self.domain), line.lower())
                            subdomains.update(matches)
                    self.logger.info(f"{Fore.GREEN}[+] crt.sh: Found {len(subdomains)} subdomains (alternative parsing){Style.RESET_ALL}")
                    return subdomains
            else:
                self.logger.warning(f"{Fore.YELLOW}[-] crt.sh: HTTP {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] crt.sh Error: {e}{Style.RESET_ALL}")
        return set()

    def hackertarget_lookup(self):
        """Query hackertarget.com for subdomains"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                subdomains = set()
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.domain}"):
                            subdomains.add(subdomain)
                self.logger.info(f"{Fore.GREEN}[+] Hackertarget: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
                return subdomains
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] Hackertarget Error: {e}{Style.RESET_ALL}")
        return set()

    def anubis_lookup(self):
        """Query anubis.cyberxplore.com for subdomains"""
        try:
            url = f"https://jonlu.ca/anubis/subdomains/{self.domain}"
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = {sub.lower() for sub in data if sub.endswith(f".{self.domain}")}
                    self.logger.info(f"{Fore.GREEN}[+] Anubis: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
                    return subdomains
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            self.logger.debug(f"[!] Anubis Error: {e}")
        return set()

    def dns_resolve(self, subdomain):
        """Resolve a subdomain to check if it exists - FIXED"""
        try:
            # Try A record first
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                ips = [str(rdata) for rdata in answers]
                return subdomain, ips
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            try:
                # Try CNAME record
                answers = self.resolver.resolve(subdomain, 'CNAME')
                if answers:
                    cnames = [str(rdata.target).rstrip('.') for rdata in answers]
                    return subdomain, cnames
            except:
                pass
        except Exception:
            pass
        return None, []

    def brute_force_subdomains(self):
        """Brute force subdomains using wordlist - FIXED"""
        if not self.wordlist:
            # Use built-in wordlist if none provided
            builtin_words = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
                'ns2', 'cpanel', 'whm', 'webdisk', 'admin', 'email', 'blog', 'shop',
                'api', 'dev', 'test', 'staging', 'mobile', 'm', 'app', 'docs', 'status'
            ]
            words = builtin_words
            self.logger.info(f"Using built-in wordlist with {len(words)} words")
        elif not os.path.exists(self.wordlist):
            self.logger.warning(f"{Fore.YELLOW}[!] Wordlist not found: {self.wordlist}{Style.RESET_ALL}")
            return set()
        else:
            try:
                with open(self.wordlist, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded wordlist with {len(words)} words")
            except Exception as e:
                self.logger.error(f"{Fore.RED}[!] Error loading wordlist: {e}{Style.RESET_ALL}")
                return set()
        
        subdomains = set()
        found_count = 0
        total_words = len(words)
        
        print(f"{Fore.CYAN}[*] Brute forcing with {total_words} words...{Style.RESET_ALL}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Create futures for all subdomains
                futures = {}
                for i, word in enumerate(words):
                    subdomain = f"{word}.{self.domain}"
                    future = executor.submit(self.dns_resolve, subdomain)
                    futures[future] = (subdomain, i+1, total_words)
                
                # Process results as they complete
                for future in as_completed(futures):
                    subdomain, current, total = futures[future]
                    try:
                        result = future.result()
                        if result[0]:  # If subdomain was found
                            found_subdomain, records = result
                            subdomains.add(found_subdomain)
                            found_count += 1
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] {found_subdomain} -> {', '.join(records[:2])}{'...' if len(records) > 2 else ''}{Style.RESET_ALL}")
                        # Show progress
                        if current % 50 == 0 or current == total:
                            print(f"{Fore.CYAN}[*] Progress: {current}/{total} words, Found: {found_count}{Style.RESET_ALL}")
                    except Exception as e:
                        if self.verbose:
                            self.logger.debug(f"Error processing {subdomain}: {e}")
            
            self.logger.info(f"{Fore.GREEN}[+] Brute Force: Found {found_count} subdomains{Style.RESET_ALL}")
            
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] Brute Force Error: {e}{Style.RESET_ALL}")
        
        return subdomains

    def securitytrails_lookup(self):
        """Query SecurityTrails API for subdomains - FIXED"""
        if not API_KEYS.get('securitytrails'):
            self.logger.warning(f"{Fore.YELLOW}[!] SecurityTrails API key not configured{Style.RESET_ALL}")
            return set()
            
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {
                'APIKEY': API_KEYS['securitytrails'],
                'User-Agent': random.choice(USER_AGENTS)
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = {f"{sub}.{self.domain}".lower() for sub in data.get('subdomains', [])}
                self.logger.info(f"{Fore.GREEN}[+] SecurityTrails: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
                return subdomains
            else:
                self.logger.warning(f"{Fore.YELLOW}[-] SecurityTrails: HTTP {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] SecurityTrails Error: {e}{Style.RESET_ALL}")
        return set()

    def virustotal_lookup(self):
        """Query VirusTotal API for subdomains"""
        if not API_KEYS.get('virustotal'):
            self.logger.warning(f"{Fore.YELLOW}[!] VirusTotal API key not configured{Style.RESET_ALL}")
            return set()
            
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {
                'x-apikey': API_KEYS['virustotal'],
                'User-Agent': random.choice(USER_AGENTS)
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for item in data.get('data', []):
                    if 'id' in item:
                        subdomain = item['id'].lower()
                        if subdomain.endswith(f".{self.domain}"):
                            subdomains.add(subdomain)
                self.logger.info(f"{Fore.GREEN}[+] VirusTotal: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
                return subdomains
        except Exception as e:
            self.logger.error(f"{Fore.RED}[!] VirusTotal Error: {e}{Style.RESET_ALL}")
        return set()

    def check_web_server(self, subdomain):
        """Check if subdomain has a web server"""
        try:
            # Try HTTP first
            url = f"http://{subdomain}"
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            title = self.extract_title(response.text)
            return {
                'subdomain': subdomain,
                'status': response.status_code,
                'title': title,
                'server': response.headers.get('Server', 'Unknown'),
                'url': url,
                'protocol': 'http'
            }
        except Exception:
            try:
                # Try HTTPS
                url = f"https://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                title = self.extract_title(response.text)
                return {
                    'subdomain': subdomain,
                    'status': response.status_code,
                    'title': title,
                    'server': response.headers.get('Server', 'Unknown'),
                    'url': url,
                    'protocol': 'https'
                }
            except Exception:
                return None

    def extract_title(self, html):
        """Extract title from HTML"""
        if not html:
            return "No Title"
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r'\s+', ' ', match.group(1).strip())
            return title[:50] + "..." if len(title) > 50 else title
        return "No Title"

    def save_results(self, subdomains):
        """Save results in various formats"""
        if not subdomains:
            self.logger.warning(f"{Fore.YELLOW}[!] No subdomains found to save{Style.RESET_ALL}")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"simplefinderz_{self.domain}_{timestamp}"
        
        # Create output directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        # Save to text file
        txt_filename = f"results/{base_filename}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"# SimpleFinderz Results\n")
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
        
        print(f"\n{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}Text:{Style.RESET_ALL} {txt_filename}")
        if self.output_format in ['json', 'both']:
            print(f"   {Fore.CYAN}JSON:{Style.RESET_ALL} {json_filename}")

    def run(self):
        """Main execution method"""
        self.display_banner()
        
        all_subdomains = set()
        start_time = time.time()
        
        print(f"{Fore.YELLOW}[*] Starting enumeration...{Style.RESET_ALL}\n")
        
        # API-based enumeration
        if self.use_apis:
            methods = [
                (self.crtsh_lookup, "Certificate Transparency (crt.sh)"),
                (self.hackertarget_lookup, "Hackertarget"),
                (self.anubis_lookup, "Anubis"),
                (self.securitytrails_lookup, "SecurityTrails"),
                (self.virustotal_lookup, "VirusTotal")
            ]
            
            for method, name in methods:
                print(f"{Fore.CYAN}[*] Querying {name}...{Style.RESET_ALL}")
                try:
                    subdomains = method()
                    new_subdomains = subdomains - all_subdomains
                    all_subdomains.update(new_subdomains)
                    if new_subdomains:
                        print(f"   {Fore.GREEN}[+] Found {len(new_subdomains)} new subdomains{Style.RESET_ALL}")
                except Exception as e:
                    print(f"   {Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        
        # DNS brute force
        if self.use_dns and self.use_wordlist:
            print(f"\n{Fore.CYAN}[*] Starting DNS brute force...{Style.RESET_ALL}")
            brute_subdomains = self.brute_force_subdomains()
            new_subdomains = brute_subdomains - all_subdomains
            all_subdomains.update(new_subdomains)
            if new_subdomains:
                print(f"   {Fore.GREEN}[+] Found {len(new_subdomains)} new subdomains via brute force{Style.RESET_ALL}")
        
        elapsed_time = time.time() - start_time
        
        # Display summary
        print(f"\n{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] SCAN COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Target Domain:{Style.RESET_ALL} {self.domain}")
        print(f"{Fore.YELLOW}Total Subdomains Found:{Style.RESET_ALL} {len(all_subdomains)}")
        print(f"{Fore.YELLOW}Scan Duration:{Style.RESET_ALL} {elapsed_time:.2f} seconds")
        if elapsed_time > 0 and len(all_subdomains) > 0:
            print(f"{Fore.YELLOW}Scan Rate:{Style.RESET_ALL} {len(all_subdomains)/elapsed_time:.2f} subdomains/sec")
        print(f"{Fore.CYAN}{'═'*70}{Style.RESET_ALL}")
        
        # Display found subdomains
        if all_subdomains:
            print(f"\n{Fore.CYAN}[*] Found Subdomains:{Style.RESET_ALL}")
            for i, subdomain in enumerate(sorted(all_subdomains), 1):
                print(f"  {i:3}. {subdomain}")
        
        # Save results
        self.save_results(all_subdomains)
        
        # Check active web servers if verbose
        if self.verbose and all_subdomains:
            print(f"\n{Fore.CYAN}[*] Checking for active web servers...{Style.RESET_ALL}")
            active_results = []
            
            with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
                futures = {executor.submit(self.check_web_server, sub): sub 
                          for sub in sorted(all_subdomains)[:50]}  # Limit to first 50
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        active_results.append(result)
                        status_color = Fore.GREEN if 200 <= result['status'] < 300 else Fore.YELLOW
                        print(f"{status_color}[+] {result['subdomain']} - HTTP {result['status']} - {result['title']}{Style.RESET_ALL}")
        
        return all_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='SimpleFinderz - Advanced Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -w wordlist.txt -t 100 -o json
  %(prog)s example.com --no-api --no-dns -v

API Configuration:
  Set environment variables for API keys:
    export VIRUSTOTAL_API_KEY="your_key"
    export SECURITYTRAILS_API_KEY="your_key"
    export SHODAN_API_KEY="your_key"
        """
    )
    
    parser.add_argument('domain', help='Target domain to enumerate')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', 
                        default=None)
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'both'],
                        default='txt', help='Output format (default: txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--no-api', action='store_true',
                        help='Disable API-based enumeration')
    parser.add_argument('--no-dns', action='store_true',
                        help='Disable DNS brute force')
    parser.add_argument('--no-wordlist', action='store_true',
                        help='Disable wordlist brute force')
    parser.add_argument('--no-ssl-verify', action='store_true',
                        help='Disable SSL certificate verification')
    
    args = parser.parse_args()
    
    # Check if domain is valid
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
        print(f"{Fore.RED}[!] Invalid domain format{Style.RESET_ALL}")
        sys.exit(1)
    
    # Disable SSL verification if requested
    if args.no_ssl_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings()
    
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
        use_wordlist=not args.no_wordlist
    )
    
    try:
        results = scanner.run()
        if not results:
            print(f"\n{Fore.YELLOW}[!] No subdomains found for {args.domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Try:{Style.RESET_ALL}")
            print(f"   1. Use a different wordlist: -w /path/to/wordlist.txt")
            print(f"   2. Enable API lookups (if disabled)")
            print(f"   3. Check your internet connection")
            print(f"   4. Try with verbose mode: -v")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()