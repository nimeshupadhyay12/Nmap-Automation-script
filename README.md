# Nmap-Automation-script

# Python Automation for Nmap Scanning

## Overview
"Python Automation for Nmap Scanning" is a powerful Python-based tool that automates network scanning using Nmap. Designed for both beginners and advanced users (e.g., ethical hackers), it offers a variety of scan types, integrates with the Exploit-DB API for real-time exploit suggestions, and provides actionable attack recommendations. With a colorful, user-friendly interface, this script simplifies network reconnaissance while empowering users to explore Nmap’s capabilities programmatically.

## Key Features
- **13 Scan Options**: Organized into Basic, Stealth, and Advanced categories with visible Nmap flags (e.g., `-sV`, `-A`).
- **Exploit Suggestions**: Fetches potential exploits from Exploit-DB (API key optional) or a static database.
- **Attack Automation**: Suggests quick exploit attempts (e.g., default credentials) and next steps for penetration testing.
- **Customizable Output**: Save results in JSON, TXT, or CSV formats.
- **Educational**: Displays Nmap flags in the menu to help users learn while scanning.
- **Ethical Focus**: Built for authorized use, such as penetration testing with permission.

## Requirements
To run this tool, you’ll need the following:

### Software
- **Python 3.6+**: Check with `python --version`.
- **Nmap**: Must be installed and accessible in your system PATH.

### Python Dependencies
Install these libraries via `pip`:
```bash
pip install -r requirements.txt
```
Or manually:
```bash
pip install python-nmap pyyaml requests colorama
```

## Installation

### Step 1: Install Prerequisites
#### Python
- Ensure Python 3.6+ is installed:
  - [Download Python](https://www.python.org/downloads/)
  - Verify: `python --version` or `python3 --version`.

#### Nmap
- **Windows**: [Download Nmap](https://nmap.org/download.html) and add it to your PATH.
- **Linux**:
  ```bash
  sudo apt-get install nmap  # Ubuntu/Debian
  sudo yum install nmap      # CentOS/RHEL
  ```
- **macOS**:
  ```bash
  brew install nmap  # Requires Homebrew
  ```
Verify installation with `nmap -v`.

### Step 2: Clone the Repository
```bash
git clone https://github.com/yourusername/python-automation-for-nmap-scanning.git
cd python-automation-for-nmap-scanning
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: (Optional) Configure Exploit-DB API
- Obtain an API key from [Exploit-DB](https://www.exploit-db.com/).
- Add it to `config.yaml`:
  ```yaml
  exploit_db_api_key: "your-api-key-here"
  ```
- Alternatively, pass it via command line: `--api-key "your-api-key-here"`.

## Usage Guide

### Running the Tool
```bash
python nmap_automation.py
```

### Command-Line Options
- `--output <filename>`: Save results (e.g., `results.json`).
- `--format <json|txt|csv>`: Output format (default: JSON).
- `--verbose`: Display detailed scan output.
- `--api-key <key>`: Use an Exploit-DB API key.
- `--config <file>`: Specify a custom config file (default: `config.yaml`).

### Interactive Mode
1. **Enter Target**: Input an IP or range (e.g., `192.168.1.1` or `192.168.1.0/24`).
2. **Specify Ports**: Enter ports (e.g., `22,80,443`) or press Enter for all (`1-65535`).
3. **Choose a Scan**: Select from 13 scan options.

### Scan Categories
#### Basic Scans:
1. Quick Peek (`-sP`) - Fast ping scan.
2. Loud Connect (`-sT`) - Simple TCP connect scan.
3. OS Guess (`-O`) - OS detection.

#### Stealth Scans:
4. SYN Stealth (`-sS`) - Half-open TCP scan.
5. Null Stealth (`-sN`) - No TCP flags.
6. FIN Stealth (`-sF`) - FIN flag scan.
7. Xmas Stealth (`-sX`) - FIN/PSH/URG flags.
8. UDP Stealth (`-sU`) - UDP port scan.

#### Advanced Scans:
9. Service Probe (`-sV`) - Service/version detection.
10. Vuln Hunt (`--script vuln`) - Vulnerability scan.
11. All-In Assault (`-A`) - Aggressive full scan.
12. Deep Sweep (`-sV -O`) - Service + OS combo.
13. Total Blitz (all flags) - Every scan type.

### Example Usage
Basic run:
```bash
python nmap_automation.py
```
With options:
```bash
python nmap_automation.py --output scan_results.json --verbose --api-key "your-api-key"
```

### Sample Interaction
```
Enter target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24): 192.168.1.1
Ports to scan (press Enter for all 1-65535):
Pick your scan:
1: Quick Peek (-sP) - Fast check if it’s alive
2: Loud Connect (-sT) - Simple and loud connect scan
3: OS Guess (-O) - Guess the target’s system
...
Enter scan number (1-13): 11
Scanning 192.168.1.1... Hold tight!
===== Scan Report for 192.168.1.1 =====
  Target Name: router.local
  Status: Up and running
  --- System Details ---
  System: Linux 4.X (95% sure)
  --- Open Ports ---
  Found: 3 open
    • Port 22: ssh (OpenSSH 7.9p1) - Remote login (SSH)
    • Port 23: telnet - Old remote login (Telnet)
    • Port 80: http (Apache 2.4.41) - Web (HTTP)
  --- Hack It! ---
    • Port 22: Exploit Idea - Brute-force or check for weak keys
    • Port 22: Quick Attack - Try SSH login with 'root:admin'...
  --- What’s Next? ---
    • Brute-force SSH with Hydra...
===== Report Done =====
```

## Project Structure
```
python-automation-for-nmap-scanning/
├── nmap_automation.py  # Main script
├── README.md          # This file
├── requirements.txt   # Dependency list
├── config.yaml        # Optional API config
├── LICENSE            # MIT License
└── .gitignore         # Ignores temp files
```

Happy Scanning! 🚀
