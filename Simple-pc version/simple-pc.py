#!/usr/bin/env python3
"""
SimpleFinder - Professional Subdomain Scanner
Author: Cyber-Specterz
Version: 1.0.0
"""

import sys
import os
import argparse
import requests
import json
import time
import dns.resolver
import socket
import re
import concurrent.futures
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

class Colors:
    """Console colors for beautiful output"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class SimpleFinder:
    def __init__(self, domain, wordlist=None, threads=50, timeout=10, 
                 output_format='txt', verbose=False):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output_format = output_format
        self.verbose = verbose
        self.found_subdomains = set()
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        })
        
        # Setup DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Create directories
        os.makedirs('results', exist_ok=True)
        os.makedirs('wordlists', exist_ok=True)

    def display_banner(self):
        """Display SimpleFinder banner"""
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
    ║             SIMPLEFINDER - PC EDITION            ║
    ║                  Version 1.0.0                   ║
    ║              Author: Cyber-Specterz              ║
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
        except Exception:
            if self.verbose:
                print(f"{Colors.YELLOW}[-] {api_name} API Error{Colors.RESET}")
        return None

    def crtsh_lookup(self):
        """Query crt.sh for subdomains"""
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
        except Exception:
            pass
        return set()

    def hackertarget_lookup(self):
        """Query Hackertarget API"""
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
        """Query ThreatCrowd API"""
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

    def dns_resolve(self, subdomain):
        """DNS resolution"""
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
        """Brute force subdomains using wordlist"""
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
                'media', 'img', 'images', 'js', 'css', 'download', 'upload', 'files',
                'mail1', 'mail2', 'mx', 'mx1', 'mx2', 'dns', 'dns1', 'dns2', 'ns',
                'ns3', 'ns4', 'webdisk', 'whm', 'server', 'server1', 'server2',
                'cluster', 'cluster1', 'cluster2', 'node', 'node1', 'node2', 'db',
                'database', 'mysql', 'mongo', 'redis', 'cache', 'git', 'svn', 'repo',
                'docker', 'k8s', 'kubernetes', 'jenkins', 'ci', 'cd', 'stage', 'staging',
                'prod', 'production', 'beta', 'alpha', 'demo', 'test1', 'test2', 'uat',
                'preprod', 'sandbox', 'play', 'playground', 'lab', 'labs', 'research',
                'dev1', 'dev2', 'development', 'staging1', 'staging2', 'production1',
                'production2', 'backup', 'backup1', 'backup2', 'monitor', 'monitoring',
                'stats', 'statistics', 'analytics', 'metric', 'metrics', 'graph',
                'graphite', 'grafana', 'prometheus', 'alert', 'alerts', 'alertmanager',
                'log', 'logs', 'logger', 'logging', 'elk', 'elastic', 'kibana', 'logstash',
                'file', 'files', 'file1', 'file2', 'storage', 'storage1', 'storage2',
                's3', 's3bucket', 'bucket', 'blob', 'blobstorage', 'azure', 'aws',
                'gcp', 'google', 'cloud', 'cloud1', 'cloud2', 'cdn1', 'cdn2', 'cdn3',
                'edge', 'edge1', 'edge2', 'origin', 'origin1', 'origin2', 'loadbalancer',
                'lb', 'lb1', 'lb2', 'haproxy', 'nginx', 'apache', 'tomcat', 'jetty',
                'jboss', 'weblogic', 'websphere', 'glassfish', 'resin', 'gunicorn',
                'uwsgi', 'php-fpm', 'fastcgi', 'scgi', 'wsgi', 'asgi', 'cgi', 'isapi',
                'nsapi', 'servlet', 'jsp', 'asp', 'aspx', 'php', 'py', 'pl', 'rb', 'go',
                'java', 'c', 'cpp', 'cs', 'vb', 'js', 'ts', 'html', 'css', 'xml', 'json',
                'yaml', 'ini', 'cfg', 'conf', 'config', 'properties', 'env', 'bashrc',
                'profile', 'bash_profile', 'bash_login', 'bash_logout', 'inputrc'
            ]
            words = default_words
        
        subdomains = set()
        found_count = 0
        total_words = len(words)
        
        print(f"{Colors.CYAN}[*] Brute forcing with {total_words} words...{Colors.RESET}")
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for word in words:
                    subdomain = f"{word}.{self.domain}"
                    futures.append(executor.submit(self.dns_resolve, subdomain))
                
                for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
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
        base_filename = f"simplefinder_{self.domain}_{timestamp}"
        
        # Save to text file
        txt_filename = f"results/{base_filename}.txt"
        with open(txt_filename, 'w') as f:
            f.write(f"# SimpleFinder Results\n")
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
        apis = [
            (self.crtsh_lookup, "Certificate Transparency"),
            (self.hackertarget_lookup, "Hackertarget API"),
            (self.threatcrowd_lookup, "ThreatCrowd"),
        ]
        
        for api_func, api_name in apis:
            print(f"{Colors.CYAN}[*] Querying {api_name}...{Colors.RESET}")
            try:
                subdomains = api_func()
                new_subdomains = subdomains - all_subdomains
                all_subdomains.update(new_subdomains)
                time.sleep(0.5)  # Rate limiting
            except Exception:
                pass
        
        # DNS brute force
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
        description='SimpleFinder - Professional Subdomain Scanner by Cyber-Specterz',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.GREEN}Examples:{Colors.RESET}
  python simplefinder.py instagram.com
  python simplefinder.py google.com -t 100 -v
  python simplefinder.py example.com -w wordlist.txt -o json
  
{Colors.YELLOW}Options:{Colors.RESET}
  -w, --wordlist    Path to custom wordlist file
  -t, --threads     Number of threads (default: 50)
  --timeout         Timeout in seconds (default: 10)
  -o, --output      Output format: txt, json, both (default: txt)
  -v, --verbose     Enable verbose output
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., instagram.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file', default=None)
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('-o', '--output', choices=['txt', 'json', 'both'], default='txt', help='Output format')
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
    scanner = SimpleFinder(
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
    print(f"{Colors.BLUE}[*] SimpleFinder v1.0.0 by Cyber-Specterz{Colors.RESET}")
    main()