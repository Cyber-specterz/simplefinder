#!/bin/bash
# PC Installation Script

echo "========================================="
echo "   SimpleFinderz PC Edition Installer"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check Python
echo -e "${BLUE}[*] Checking Python...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Python3 not found!${NC}"
    echo "Please install Python 3.7+ from:"
    echo "  https://www.python.org/downloads/"
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

# Download wordlist
echo -e "${BLUE}[*] Downloading wordlist...${NC}"
curl -s -o wordlists/default.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
echo -e "${GREEN}[+] Wordlist downloaded (5000 entries)${NC}"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Installation Complete!               ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  python simplefinderz-pc.py instagram.com"
echo ""
echo -e "${YELLOW}Advanced:${NC}"
echo "  python simplefinderz-pc.py google.com -t 100 -v -o json"
echo ""