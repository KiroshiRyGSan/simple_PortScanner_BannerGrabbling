# Simple Python Port Scanner & Banner Grabber

A lightweight, efficient Python tool designed to identify open ports on a target host and retrieve service banners. This tool is ideal for basic network reconnaissance and security auditing.

## 🚀 Features

- **Port Scanning**: Quickly checks if TCP ports are open or closed.
- **Banner Grabbing**: Attempts to retrieve the service version/information from open ports.
- **Flexible Port Selection**: Supports single ports, comma-separated lists, and ranges using the `*` syntax.
- **Logging**: Automatically saves scan results to a `result.txt` file for later review.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/your-username/VP_portscanner.git](https://github.com/your-username/VP_portscanner.git)
   cd VP_portscanner
   
2. **(Optional) Create a virtual environment**:
   It is recommended to use a virtual environment to keep your global Python installation clean.
   ```bash
   # Create the environment
   python -m venv venv

   # Activate it on Windows:
   .\venv\Scripts\activate

   # Activate it on Linux/macOS:
   source venv/bin/activate
   
3. **Dependencies**:
   This project is built using **Python Standard Libraries**.
   - `socket`: Used for network connections and banner retrieval.
   - `argparse`: Used for professional command-line argument parsing.
   
   No external `pip` installations are required, making the tool extremely portable.

## 📖 Usage

Run the script from your terminal. You must provide a target host and the ports you wish to scan.

    python portscanner.py -H <target_host> -p <port_selection>

Port Selection Syntax
The scanner supports three flexible input formats for the -p flag:

Single Port: -p 80

Multiple Ports: -p 22,80,443 (comma-separated)

Range of Ports: -p 21*100 (scans all ports from 21 to 100)

🖥️ Examples
Scan specific services:

    python portscanner.py -H 127.0.0.1 -p 80,443,3306

Scan a wide range of ports:

    python portscanner.py -H 192.168.1.10 -p 1*1024

📝 Output & Logging
The tool identifies open ports and attempts Banner Grabbing to extract service information (e.g., SSH version, Web server type).

Results are displayed in the terminal and automatically saved to result.txt. The log file includes:

Target Host and resolved IP.

Status of each scanned port.

Captured service banners (if available).

⚠️ Disclaimer
This tool is intended for educational and ethical security testing only. Scanning targets without explicit prior consent is illegal and unethical. The author holds no responsibility for misuse.