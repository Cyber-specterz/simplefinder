# Simple Finder 🔍

**Simple Finder** is a high-performance subdomain enumeration tool designed for security researchers, penetration testers, and system administrators. It combines multiple enumeration techniques with a beautiful interface and powerful features to discover subdomains efficiently.

![Simple Finder Banner](https://img.shields.io/badge/Simple-Finder-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Termux-lightgrey)

## ✨ Features

### 🎯 Core Capabilities
- **Multi-Source Enumeration**: Combine results from certificate transparency logs, public APIs, and DNS brute force
- **Smart DNS Resolution**: Fast and accurate subdomain discovery with intelligent caching
- **Parallel Processing**: Multi-threaded scanning (50+ threads on PC, 15+ on Termux)
- **Real-time Validation**: Instant validation of discovered subdomains

### 🎨 Beautiful Interface
- **Professional ASCII Banner**: Eye-catching tool branding
- **Color-coded Output**: Easy-to-read console output with status indicators
- **Progress Tracking**: Real-time progress bars and statistics
- **Clean Organization**: Well-structured results with timestamps

### 📊 Output Formats
- **Text Format**: Clean, readable output for manual review
- **JSON Format**: Structured data for automation and integration
- **Auto-save**: Automatic file naming with timestamps
- **Multiple Export Options**: Export to various formats as needed

### ⚡ Performance
- **High-Speed Scanning**: Optimized algorithms for fast enumeration
- **Resource Efficient**: Minimal memory footprint with intelligent caching
- **Rate Limiting**: Built-in protection to avoid API bans
- **Smart Retry Logic**: Automatic retry for failed requests

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- `pip` package manager

### Installation

#### For PC (Windows/Linux/macOS):
```bash
# Clone the repository
git clone https://github.com/cyber-specterz/simple-finder.git
cd simple-finder

# Install dependencies
pip install -r requirements.txt

# Run Simple Finder
python simple_finder.py --help


