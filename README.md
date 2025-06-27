# NetSentinel - Real-Time Network Threat Visualizer

A python based network security tool that provides real-time visualization and monitoring of your local network and helps unknown devices connected and potential security threats and unusual network behavior through an intuitive interface.

## Features

- 🔍 **Device Discovery**: Automatically scans and identifies all devices on your local network
- 📊 **Live Dashboard**: Real-time visualization of network activity
- 🚨 **Threat Detection**: Identifies suspicious behavior and potential security risks
- 📱 **Device Tracking**: Monitors device bandwidth usage and active services

## Prerequisites

- Python 3.8+
- Node.js 16+
- Nmap
- Administrator/Root privileges (required for network scanning)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/netsentinel.git
cd netsentinel
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
```


## Usage

1. Start the backend server:
```bash
python backend/main.py
```

2. Start the frontend development server:
```bash
cd frontend
npm start
```

3. Access the application at `http://localhost:3000`

## Security Notice

This tool requires administrator/root privileges to perform network scanning. Please use responsibly and only on networks you own or have permission to scan.
