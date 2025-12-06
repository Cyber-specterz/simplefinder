#!/data/data/com.termux/files/usr/bin/bash

echo "========================================="
echo "   SimpleFinderz Termux Installer"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Update Termux
echo -e "${BLUE}[*] Updating Termux...${NC}"
pkg update -y && pkg upgrade -y

# Install required packages
echo -e "${BLUE}[*] Installing dependencies...${NC}"
pkg install python python-pip git curl wget dnsutils -y

# Install Python packages
echo -e "${BLUE}[*] Installing Python packages...${NC}"
pip install --upgrade pip
pip install requests

# Test if dnspython works
echo -e "${BLUE}[*] Testing DNS resolver...${NC}"
pip install dnspython 2>/dev/null && echo -e "${GREEN}[+] dnspython installed${NC}" || echo -e "${YELLOW}[-] Using alternative DNS methods${NC}"

# Create directory
echo -e "${BLUE}[*] Setting up directories...${NC}"
cd ~
mkdir -p simplefinderz
cd simplefinderz
mkdir -p wordlists results

# Create wordlist
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

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}   Installation Complete!               ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  python simplefinderz-termux.py instagram.com"
echo ""
echo -e "${YELLOW}Advanced:${NC}"
echo "  python simplefinderz-termux.py google.com -t 15 -v"
echo ""
echo -e "${YELLOW}Access Results:${NC}"
echo "  cp results/*.txt ~/storage/shared/Download/"
echo ""