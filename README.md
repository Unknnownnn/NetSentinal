# NetSentinel - Real-Time Network Threat Visualizer

NetSentinel is a consumer-facing network security tool that provides real-time visualization and monitoring of your local network. It helps identify potential security threats and unusual network behavior through an intuitive and beautiful interface.

## Features

- 🔍 **Device Discovery**: Automatically scans and identifies all devices on your local network
- 📊 **Live Dashboard**: Beautiful real-time visualization of network activity
- 🚨 **Threat Detection**: Identifies suspicious behavior and potential security risks
- 📱 **Device Tracking**: Monitors device bandwidth usage and active services
- 🔔 **Alert System**: Real-time notifications for new device connections
- 📋 **Network Reports**: Export detailed network analysis reports

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

4. Create a .env file in the root directory:
```bash
SCAN_INTERVAL=300  # Network scan interval in seconds
JWT_SECRET=your_secret_key
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

## License

MIT License - See LICENSE file for details 