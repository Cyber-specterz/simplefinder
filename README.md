🔍 SimpleFinder - Professional Subdomain Scanner
<p align="center"> <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version"> <img src="https://img.shields.io/badge/Python-3.7+-green.svg" alt="Python"> <img src="https://img.shields.io/badge/Platform-PC%20%7C%20Termux-lightgrey.svg" alt="Platform"> <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"> <img src="https://img.shields.io/badge/Maintained-Yes-success.svg" alt="Maintained"> </p><p align="center"> <b>⚡ Advanced Subdomain Discovery Tool with Beautiful CLI Interface ⚡</b> </p><p align="center"> <img src="https://i.imgur.com/placeholder.png" width="600" alt="SimpleFinder Banner"> </p>
📋 Table of Contents
✨ Features

🚀 Quick Start

🖥️ PC Installation

📱 Termux Installation

🎯 Usage Guide

📊 Output Examples

🔧 Advanced Usage

🤝 Contributing

📄 License

⭐ Support

✨ Features
🎯 Core Capabilities
Multi-Source Enumeration: Combine results from certificate transparency logs, public APIs, and DNS brute force

Smart DNS Resolution: Fast and accurate subdomain discovery with intelligent caching

Parallel Processing: Multi-threaded scanning for maximum efficiency (50+ threads on PC, 15+ on Termux)

Real-time Validation: Instant validation of discovered subdomains

🎨 Beautiful Interface
Professional ASCII Banner: Eye-catching tool branding

Color-coded Output: Easy-to-read console output with status indicators

Progress Tracking: Real-time progress bars and statistics

Clean Organization: Well-structured results with timestamps

📊 Output Formats
Text Format: Clean, readable output for manual review

JSON Format: Structured data for automation and integration

Auto-save: Automatic file naming with timestamps

Multiple Export Options: Export to various formats as needed

⚡ Performance
High-Speed Scanning: Optimized algorithms for fast enumeration

Resource Efficient: Minimal memory footprint with intelligent caching

Rate Limiting: Built-in protection to avoid API bans

Smart Retry Logic: Automatic retry for failed requests



🚀 Quick Start
For PC (Windows/Linux/macOS):

# Clone the repository
git clone https://github.com/Cyber-Specterz/simplefinder.git
cd simplefinder

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python simplefinder.py instagram.com

For Termux (Android):

# Install Termux from F-Droid, then:
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/Cyber-Specterz/simplefinder.git
cd simplefinder
python simplefinder-termux.py google.com

🖥️ PC Installation
Prerequisites
Python 3.7+ (Download)

pip (Python package manager)

Git (optional, for cloning)

