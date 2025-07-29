# NetSentinel Configuration File
# Customize security settings, thresholds, and network parameters

import logging

# Network Configuration
NETWORK_CONFIG = {
    "default_interface": None,  # Auto-detect if None
    "scan_timeout": 10,  # seconds
    "packet_capture_timeout": 60,  # seconds
    "max_devices": 1000,  # Maximum devices to track
    "device_timeout": 3600,  # Remove inactive devices after 1 hour
}

# Security Monitor Configuration
SECURITY_CONFIG = {
    # Trust Score Thresholds
    "trust_score_threshold": 70,  # Below this triggers alerts
    "high_risk_threshold": 30,   # Below this triggers immediate action
    
    # Rate Limiting
    "max_packets_per_minute": 1000,
    "max_connections_per_minute": 100,
    "max_failed_attempts": 5,
    
    # Behavior Analysis
    "unusual_traffic_threshold": 10000,  # bytes per minute
    "suspicious_port_scan_threshold": 10,  # ports scanned
    "max_dhcp_requests": 5,  # per hour
    
    # Time Windows (in seconds)
    "analysis_window": 300,  # 5 minutes
    "alert_cooldown": 60,    # 1 minute between similar alerts
    
    # Auto Actions
    "auto_quarantine_enabled": True,
    "auto_block_enabled": False,  # Requires manual approval
    "auto_deauth_enabled": False,  # High risk action
}

# Network Defense Configuration
DEFENSE_CONFIG = {
    "deauth_packet_count": 10,
    "arp_poison_interval": 1,  # seconds
    "block_duration": 3600,    # 1 hour default
    "quarantine_vlan": 666,    # VLAN for quarantined devices
    
    # Ping Configuration
    "ping_timeout": 5,
    "ping_count": 4,
    "ping_interval": 1,
}

# Vulnerability Scanner Configuration
VULN_SCANNER_CONFIG = {
    "nmap_timeout": 300,  # 5 minutes
    "default_ports": "1-1000",
    "aggressive_scan": False,
    "service_detection": True,
    "os_detection": False,  # Can be slow
    
    # Common vulnerable ports to always check
    "critical_ports": [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        27017, # MongoDB
    ],
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": logging.INFO,
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "netsentinel.log",
    "max_size": 10 * 1024 * 1024,  # 10MB
    "backup_count": 5,
}

# API Configuration
API_CONFIG = {
    "host": "127.0.0.1",
    "port": 8000,
    "cors_origins": ["http://localhost:3000"],
    "websocket_ping_interval": 30,
    "max_connections": 100,
}

# Database Configuration (for future use)
DATABASE_CONFIG = {
    "type": "sqlite",  # sqlite, postgresql, mysql
    "name": "netsentinel.db",
    "host": "localhost",
    "port": 5432,
    "username": "",
    "password": "",
}

# Alert Notifications (for future implementation)
NOTIFICATION_CONFIG = {
    "email_enabled": False,
    "smtp_server": "",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_password": "",
    "alert_email": "",
    
    "webhook_enabled": False,
    "webhook_url": "",
    
    "slack_enabled": False,
    "slack_webhook": "",
}

# Device Classification Rules
DEVICE_CLASSIFICATION = {
    # MAC OUI patterns for device types
    "mobile_ouis": [
        "28:F0:76",  # Apple iPhone
        "40:A6:D9",  # Apple iPhone
        "58:40:4E",  # Apple iPhone
        "AC:BC:32",  # Samsung Galaxy
        "C4:43:8F",  # Samsung Galaxy
    ],
    
    "iot_ouis": [
        "18:B4:30",  # Nest
        "44:61:32",  # Ubiquiti
        "B4:75:0E",  # Amazon Echo
        "50:DC:E7",  # Amazon Echo
    ],
    
    # Hostname patterns
    "hostname_patterns": {
        "mobile": ["iphone", "android", "galaxy", "pixel"],
        "iot": ["nest", "echo", "alexa", "ring", "hue"],
        "printer": ["hp", "canon", "epson", "brother"],
        "router": ["router", "gateway", "access-point", "ap"],
        "security": ["camera", "nvr", "dvr", "security"],
    }
}

# Threat Intelligence (basic patterns)
THREAT_PATTERNS = {
    # Suspicious hostnames
    "malicious_hostnames": [
        "malware",
        "botnet", 
        "trojan",
        "backdoor",
        "keylogger",
    ],
    
    # Suspicious MAC patterns (fake/random MACs)
    "suspicious_mac_patterns": [
        "00:00:00",  # Invalid MAC
        "FF:FF:FF",  # Broadcast
        "02:00:00",  # Locally administered (potentially spoofed)
    ],
    
    # Port scan patterns
    "scan_signatures": {
        "nmap_default": [22, 80, 443, 21, 25, 53, 110, 995, 993, 143],
        "masscan": list(range(1, 65536, 1000)),  # Every 1000th port
        "zmap": [80, 443, 22, 21, 25],
    }
}

# Performance Monitoring
PERFORMANCE_CONFIG = {
    "max_memory_usage": 512 * 1024 * 1024,  # 512MB
    "max_cpu_usage": 80,  # Percent
    "metrics_interval": 60,  # seconds
    "cleanup_interval": 300,  # 5 minutes
}

def get_config():
    """Get all configuration as a dictionary"""
    return {
        "network": NETWORK_CONFIG,
        "security": SECURITY_CONFIG,
        "defense": DEFENSE_CONFIG,
        "vulnerability": VULN_SCANNER_CONFIG,
        "logging": LOGGING_CONFIG,
        "api": API_CONFIG,
        "database": DATABASE_CONFIG,
        "notifications": NOTIFICATION_CONFIG,
        "classification": DEVICE_CLASSIFICATION,
        "threats": THREAT_PATTERNS,
        "performance": PERFORMANCE_CONFIG,
    }

def update_config(section, key, value):
    """Update a configuration value"""
    config_sections = {
        "network": NETWORK_CONFIG,
        "security": SECURITY_CONFIG,
        "defense": DEFENSE_CONFIG,
        "vulnerability": VULN_SCANNER_CONFIG,
        "logging": LOGGING_CONFIG,
        "api": API_CONFIG,
        "database": DATABASE_CONFIG,
        "notifications": NOTIFICATION_CONFIG,
        "classification": DEVICE_CLASSIFICATION,
        "threats": THREAT_PATTERNS,
        "performance": PERFORMANCE_CONFIG,
    }
    
    if section in config_sections and key in config_sections[section]:
        config_sections[section][key] = value
        return True
    return False
