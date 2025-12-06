#!/bin/bash
# PC Installation Script for SimpleFinder

echo "========================================="
echo "   SimpleFinder PC Edition Installer"
echo "   Author: Cyber-Specterz"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check Python
echo -e "${BLUE}[*] Checking Python installation...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Python3 not found!${NC}"
    echo "Please install Python 3.7+ from: https://www.python.org/downloads/"
    exit 1
fi

# Create virtual environment
echo -e "${BLUE}[*] Creating virtual environment...${NC}"
python3 -m venv venv
if [ $? -eq 0 ]; then
    source venv/bin/activate
    echo -e "${GREEN}[+] Virtual environment activated${NC}"
else
    echo -e "${YELLOW}[-] Using system Python${NC}"
fi

# Install requirements
echo -e "${BLUE}[*] Installing dependencies...${NC}"
pip install --upgrade pip
pip install requests dnspython colorama

# Verify installation
echo -e "${BLUE}[*] Verifying installation...${NC}"
python3 -c "import requests; print('✓ requests:', requests.__version__)"
python3 -c "import dns; print('✓ dnspython:', dns.__version__)"
python3 -c "import colorama; print('✓ colorama installed')"

# Create directories
echo -e "${BLUE}[*] Setting up directories...${NC}"
mkdir -p wordlists results

# Download default wordlist
echo -e "${BLUE}[*] Downloading wordlist...${NC}"
curl -s -o wordlists/default.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
if [ $? -eq 0 ]; then
    word_count=$(wc -l < wordlists/default.txt)
    echo -e "${GREEN}[+] Wordlist downloaded (${word_count} entries)${NC}"
else
    echo -e "${YELLOW}[*] Creating default wordlist...${NC}"
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
    echo -e "${GREEN}[+] Default wordlist created${NC}"
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Installation Complete!               ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  python simplefinder.py instagram.com"
echo ""
echo -e "${YELLOW}Advanced Scan:${NC}"
echo "  python simplefinder.py google.com -t 100 -v -o json"
echo ""
echo -e "${YELLOW}Wordlist Usage:${NC}"
echo "  python simplefinder.py target.com -w wordlists/default.txt"
echo ""