#!/usr/bin/env python3
"""
Advanced Security Monitoring Module for NetSentinel
Provides threat detection, device authentication, and security alerts
"""

import asyncio
import time
import subprocess
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
import threading
import queue
import json
import hashlib
from scapy.all import *
import nmap

class SecurityMonitor:
    """Advanced security monitoring and threat detection"""
    
    def __init__(self):
        self.known_devices: Dict[str, dict] = {}
        self.suspicious_activity: Dict[str, list] = defaultdict(list)
        self.alert_queue = queue.Queue()
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Security thresholds
        self.thresholds = {
            'port_scan_threshold': 20,  # ports accessed in 5 minutes
            'connection_burst_threshold': 50,  # connections in 1 minute
            'data_exfiltration_threshold': 100 * 1024 * 1024,  # 100MB in 5 minutes
            'failed_auth_threshold': 5,  # failed authentications
            'dns_tunnel_threshold': 100,  # DNS queries per minute
            'beacon_threshold': 10,  # regular connections to same external IP
        }
        
        # Tracking data structures
        self.port_access_history = defaultdict(lambda: deque(maxlen=100))
        self.connection_history = defaultdict(lambda: deque(maxlen=200))
        self.data_transfer_history = defaultdict(lambda: deque(maxlen=50))
        self.dns_query_history = defaultdict(lambda: deque(maxlen=500))
        self.auth_failure_history = defaultdict(lambda: deque(maxlen=20))
        
        # Known attack patterns
        self.attack_signatures = self._load_attack_signatures()
        
        # Device fingerprinting
        self.device_fingerprints = {}
        
    def _load_attack_signatures(self) -> Dict[str, dict]:
        """Load known attack patterns and signatures"""
        return {
            'nmap_scan': {
                'pattern': 'rapid_port_access',
                'description': 'Potential Nmap scan detected',
                'severity': 'high',
                'indicators': ['rapid_port_sequence', 'syn_scan_pattern']
            },
            'brute_force': {
                'pattern': 'repeated_auth_failures',
                'description': 'Brute force attack detected',
                'severity': 'critical',
                'indicators': ['multiple_failed_logins', 'common_passwords']
            },
            'dns_tunneling': {
                'pattern': 'excessive_dns_queries',
                'description': 'DNS tunneling detected',
                'severity': 'high',
                'indicators': ['unusual_dns_volume', 'long_dns_queries']
            },
            'data_exfiltration': {
                'pattern': 'large_data_transfer',
                'description': 'Potential data exfiltration',
                'severity': 'critical',
                'indicators': ['large_outbound_transfer', 'encrypted_channel']
            },
            'mitm_attack': {
                'pattern': 'arp_spoofing',
                'description': 'Man-in-the-middle attack detected',
                'severity': 'critical',
                'indicators': ['duplicate_mac', 'arp_inconsistency']
            },
            'rogue_device': {
                'pattern': 'unauthorized_device',
                'description': 'Unauthorized device detected',
                'severity': 'medium',
                'indicators': ['unknown_mac', 'suspicious_behavior']
            }
        }
    
    def start_monitoring(self):
        """Start security monitoring"""
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("Security monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for suspicious patterns every 10 seconds
                self._analyze_suspicious_patterns()
                time.sleep(10)
            except Exception as e:
                print(f"Error in security monitor loop: {e}")
                time.sleep(5)
    
    def register_device(self, mac: str, device_info: dict, is_authorized: bool = False):
        """Register a known device"""
        fingerprint = self._generate_device_fingerprint(device_info)
        
        self.known_devices[mac] = {
            'info': device_info,
            'fingerprint': fingerprint,
            'authorized': is_authorized,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'trust_score': 100 if is_authorized else 50,
            'behavior_baseline': {}
        }
        
        self.device_fingerprints[mac] = fingerprint
        print(f"Device registered: {mac} ({'authorized' if is_authorized else 'unknown'})")
    
    def _generate_device_fingerprint(self, device_info: dict) -> str:
        """Generate unique fingerprint for device"""
        fingerprint_data = {
            'vendor': device_info.get('vendor', 'Unknown'),
            'device_type': device_info.get('device_type', 'Unknown'),
            'hostname': device_info.get('hostname', 'Unknown'),
            'os_guess': device_info.get('os_type', 'Unknown'),
            'open_ports': sorted(list(device_info.get('open_ports', set())))
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def analyze_packet(self, packet, src_ip: str, dst_ip: str, src_mac: str = None):
        """Analyze packet for security threats"""
        try:
            current_time = time.time()
            
            # Track port access patterns
            if TCP in packet or UDP in packet:
                proto = TCP if TCP in packet else UDP
                dst_port = packet[proto].dport
                self.port_access_history[src_ip].append((dst_port, current_time))
                
                # Check for port scanning
                self._check_port_scanning(src_ip)
            
            # Track connection patterns
            if TCP in packet and packet[TCP].flags == 2:  # SYN packet
                self.connection_history[src_ip].append(current_time)
                self._check_connection_burst(src_ip)
            
            # Track data transfer
            packet_size = len(packet)
            self.data_transfer_history[src_ip].append((packet_size, current_time))
            self._check_data_exfiltration(src_ip)
            
            # Track DNS queries
            if DNS in packet and packet[DNS].qr == 0:  # DNS query
                self.dns_query_history[src_ip].append(current_time)
                self._check_dns_tunneling(src_ip, packet)
            
            # Check for ARP spoofing
            if ARP in packet:
                self._check_arp_spoofing(packet)
            
            # Check device behavior against baseline
            if src_mac and src_mac in self.known_devices:
                self._analyze_device_behavior(src_mac, packet)
                
        except Exception as e:
            print(f"Error analyzing packet for security: {e}")
    
    def _check_port_scanning(self, src_ip: str):
        """Detect port scanning behavior"""
        current_time = time.time()
        recent_ports = []
        
        # Check ports accessed in last 5 minutes
        for port, timestamp in self.port_access_history[src_ip]:
            if current_time - timestamp <= 300:  # 5 minutes
                recent_ports.append(port)
        
        unique_ports = len(set(recent_ports))
        if unique_ports >= self.thresholds['port_scan_threshold']:
            self._generate_alert(
                'port_scan',
                'high',
                f"Port scanning detected from {src_ip} - {unique_ports} ports accessed",
                {'source_ip': src_ip, 'ports_count': unique_ports, 'ports': list(set(recent_ports))}
            )
    
    def _check_connection_burst(self, src_ip: str):
        """Detect connection burst patterns"""
        current_time = time.time()
        recent_connections = []
        
        # Check connections in last minute
        for timestamp in self.connection_history[src_ip]:
            if current_time - timestamp <= 60:  # 1 minute
                recent_connections.append(timestamp)
        
        if len(recent_connections) >= self.thresholds['connection_burst_threshold']:
            self._generate_alert(
                'connection_burst',
                'medium',
                f"Connection burst detected from {src_ip} - {len(recent_connections)} connections in 1 minute",
                {'source_ip': src_ip, 'connection_count': len(recent_connections)}
            )
    
    def _check_data_exfiltration(self, src_ip: str):
        """Detect potential data exfiltration"""
        current_time = time.time()
        total_bytes = 0
        
        # Check data transfer in last 5 minutes
        for size, timestamp in self.data_transfer_history[src_ip]:
            if current_time - timestamp <= 300:  # 5 minutes
                total_bytes += size
        
        if total_bytes >= self.thresholds['data_exfiltration_threshold']:
            self._generate_alert(
                'data_exfiltration',
                'critical',
                f"Large data transfer detected from {src_ip} - {total_bytes / (1024*1024):.2f} MB in 5 minutes",
                {'source_ip': src_ip, 'bytes_transferred': total_bytes}
            )
    
    def _check_dns_tunneling(self, src_ip: str, packet):
        """Detect DNS tunneling attempts"""
        current_time = time.time()
        recent_queries = []
        
        # Check DNS queries in last minute
        for timestamp in self.dns_query_history[src_ip]:
            if current_time - timestamp <= 60:  # 1 minute
                recent_queries.append(timestamp)
        
        if len(recent_queries) >= self.thresholds['dns_tunnel_threshold']:
            # Additional check for suspicious query patterns
            if DNS in packet and DNSQR in packet:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                if len(query) > 50 or any(char.isdigit() for char in query[:20]):  # Long or encoded queries
                    self._generate_alert(
                        'dns_tunneling',
                        'high',
                        f"DNS tunneling detected from {src_ip} - {len(recent_queries)} queries/minute",
                        {'source_ip': src_ip, 'query_count': len(recent_queries), 'sample_query': query}
                    )
    
    def _check_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if packet[ARP].op == 2:  # ARP reply
                sender_ip = packet[ARP].psrc
                sender_mac = packet[ARP].hwsrc
                
                # Check if we've seen this IP with a different MAC
                for known_mac, device_info in self.known_devices.items():
                    if (device_info['info'].get('ip') == sender_ip and 
                        known_mac != sender_mac):
                        self._generate_alert(
                            'arp_spoofing',
                            'critical',
                            f"ARP spoofing detected - IP {sender_ip} claimed by multiple MACs",
                            {
                                'victim_ip': sender_ip,
                                'original_mac': known_mac,
                                'spoofed_mac': sender_mac
                            }
                        )
        except Exception as e:
            print(f"Error checking ARP spoofing: {e}")
    
    def _analyze_device_behavior(self, mac: str, packet):
        """Analyze device behavior against established baseline"""
        try:
            device = self.known_devices[mac]
            current_time = time.time()
            
            # Update last seen
            device['last_seen'] = datetime.now().isoformat()
            
            # Check if device behavior matches fingerprint
            if TCP in packet or UDP in packet:
                proto = TCP if TCP in packet else UDP
                port = packet[proto].dport
                
                # Check if this is unusual port usage for this device
                baseline_ports = device['behavior_baseline'].get('common_ports', set())
                if baseline_ports and port not in baseline_ports and port not in [80, 443, 53]:
                    device['trust_score'] = max(0, device['trust_score'] - 5)
                    
                    if device['trust_score'] < 30:
                        self._generate_alert(
                            'anomalous_behavior',
                            'medium',
                            f"Device {mac} showing anomalous behavior - trust score dropped to {device['trust_score']}",
                            {'device_mac': mac, 'trust_score': device['trust_score'], 'unusual_port': port}
                        )
        except Exception as e:
            print(f"Error analyzing device behavior: {e}")
    
    def _analyze_suspicious_patterns(self):
        """Analyze collected data for suspicious patterns"""
        try:
            current_time = time.time()
            
            # Check for beacon patterns (regular communications)
            for src_ip in self.connection_history:
                self._check_beacon_pattern(src_ip, current_time)
            
            # Update device baselines
            self._update_device_baselines()
            
        except Exception as e:
            print(f"Error analyzing suspicious patterns: {e}")
    
    def _check_beacon_pattern(self, src_ip: str, current_time: float):
        """Check for beacon-like communication patterns"""
        connections = list(self.connection_history[src_ip])
        if len(connections) < 10:
            return
        
        # Check for regular intervals (potential C&C beaconing)
        intervals = []
        for i in range(1, len(connections)):
            interval = connections[i] - connections[i-1]
            intervals.append(interval)
        
        if len(intervals) >= 5:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # If variance is low (regular intervals) and connections span significant time
            if variance < avg_interval * 0.1 and (connections[-1] - connections[0]) > 600:  # 10 minutes
                self._generate_alert(
                    'beacon_pattern',
                    'high',
                    f"Beacon pattern detected from {src_ip} - regular communication every {avg_interval:.1f}s",
                    {'source_ip': src_ip, 'interval': avg_interval, 'variance': variance}
                )
    
    def _update_device_baselines(self):
        """Update behavior baselines for known devices"""
        for mac, device in self.known_devices.items():
            # Update common ports baseline
            if mac in self.port_access_history:
                recent_ports = []
                current_time = time.time()
                for port, timestamp in self.port_access_history[mac]:
                    if current_time - timestamp <= 3600:  # Last hour
                        recent_ports.append(port)
                
                if recent_ports:
                    device['behavior_baseline']['common_ports'] = set(recent_ports)
    
    def _generate_alert(self, alert_type: str, severity: str, message: str, details: dict):
        """Generate security alert"""
        alert = {
            'id': hashlib.md5(f"{alert_type}_{time.time()}".encode()).hexdigest()[:8],
            'type': alert_type,
            'severity': severity,
            'message': message,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'resolved': False
        }
        
        self.alert_queue.put(alert)
        self.suspicious_activity[alert_type].append(alert)
        print(f"🚨 SECURITY ALERT [{severity.upper()}]: {message}")
    
    def get_alerts(self, limit: int = 100) -> List[dict]:
        """Get recent security alerts"""
        alerts = []
        try:
            while not self.alert_queue.empty() and len(alerts) < limit:
                alerts.append(self.alert_queue.get_nowait())
        except queue.Empty:
            pass
        return alerts
    
    def get_device_trust_score(self, mac: str) -> int:
        """Get trust score for a device"""
        if mac in self.known_devices:
            return self.known_devices[mac]['trust_score']
        return 0
    
    def whitelist_device(self, mac: str):
        """Add device to whitelist"""
        if mac in self.known_devices:
            self.known_devices[mac]['authorized'] = True
            self.known_devices[mac]['trust_score'] = 100
            print(f"Device {mac} added to whitelist")
    
    def blacklist_device(self, mac: str):
        """Add device to blacklist"""
        if mac in self.known_devices:
            self.known_devices[mac]['authorized'] = False
            self.known_devices[mac]['trust_score'] = 0
            print(f"Device {mac} added to blacklist")


class NetworkDefense:
    """Network defense and active protection measures"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.defense_active = False
        self.blocked_devices: Set[str] = set()
        self.quarantined_devices: Set[str] = set()
        
    def ping_device(self, ip: str, count: int = 4) -> dict:
        """Ping a device and return results"""
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n {count} {ip}"
            else:
                cmd = f"ping -c {count} {ip}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Parse ping results
            output = result.stdout
            packet_loss = 0
            avg_time = 0
            
            if "Lost = " in output:  # Windows
                loss_line = [line for line in output.split('\n') if 'Lost = ' in line][0]
                packet_loss = int(loss_line.split('Lost = ')[1].split(' ')[0])
                
                if 'Average = ' in output:
                    avg_line = [line for line in output.split('\n') if 'Average = ' in line][0]
                    avg_time = int(avg_line.split('Average = ')[1].replace('ms', ''))
            
            elif "packet loss" in output.lower():  # Linux/Unix
                loss_line = [line for line in output.split('\n') if 'packet loss' in line][0]
                packet_loss = float(loss_line.split('%')[0].split()[-1])
                
                if 'avg' in output:
                    stats_line = [line for line in output.split('\n') if 'avg' in line][0]
                    avg_time = float(stats_line.split('/')[1])
            
            return {
                'success': result.returncode == 0,
                'packet_loss': packet_loss,
                'avg_response_time': avg_time,
                'output': output,
                'reachable': packet_loss < 100
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'packet_loss': 100,
                'avg_response_time': 0,
                'reachable': False
            }
    
    def deauth_device(self, target_mac: str, gateway_mac: str, interface: str = None) -> dict:
        """Send deauthentication packets to disconnect a device"""
        try:
            if not interface:
                interface = self.interface
            
            if not interface:
                return {'success': False, 'error': 'No interface specified'}
            
            print(f"Sending deauth packets to {target_mac} via {gateway_mac}")
            
            # Create deauth packets
            # Deauth from client to AP
            deauth1 = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac) / Dot11Deauth()
            # Deauth from AP to client  
            deauth2 = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
            
            # Send multiple deauth packets
            for _ in range(10):
                sendp(deauth1, iface=interface, verbose=0)
                sendp(deauth2, iface=interface, verbose=0)
                time.sleep(0.1)
            
            return {
                'success': True,
                'message': f'Deauth packets sent to {target_mac}',
                'packets_sent': 20
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Deauth failed: {str(e)}'
            }
    
    def block_device_arp(self, target_ip: str, target_mac: str, gateway_ip: str) -> dict:
        """Block device using ARP spoofing"""
        try:
            print(f"Blocking device {target_mac} ({target_ip}) using ARP spoofing")
            
            # Get our MAC address
            our_mac = get_if_hwaddr(self.interface) if self.interface else "02:00:00:00:00:00"
            
            # Create ARP responses to poison both directions
            # Tell target that we are the gateway
            arp_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=our_mac)
            # Tell gateway that we are the target
            arp_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=our_mac)
            
            # Send poisoning packets
            for _ in range(5):
                send(arp_to_target, verbose=0)
                send(arp_to_gateway, verbose=0)
                time.sleep(1)
            
            self.blocked_devices.add(target_mac)
            
            return {
                'success': True,
                'message': f'Device {target_mac} blocked using ARP spoofing',
                'method': 'arp_spoofing'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'ARP block failed: {str(e)}'
            }
    
    def quarantine_device(self, mac: str, reason: str = "Suspicious activity") -> dict:
        """Quarantine a device (add to monitored list)"""
        try:
            self.quarantined_devices.add(mac)
            
            return {
                'success': True,
                'message': f'Device {mac} quarantined',
                'reason': reason,
                'quarantined_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Quarantine failed: {str(e)}'
            }
    
    def release_quarantine(self, mac: str) -> dict:
        """Release device from quarantine"""
        try:
            if mac in self.quarantined_devices:
                self.quarantined_devices.remove(mac)
                return {
                    'success': True,
                    'message': f'Device {mac} released from quarantine'
                }
            else:
                return {
                    'success': False,
                    'error': f'Device {mac} not in quarantine'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Release failed: {str(e)}'
            }
    
    def get_quarantined_devices(self) -> List[str]:
        """Get list of quarantined devices"""
        return list(self.quarantined_devices)
    
    def get_blocked_devices(self) -> List[str]:
        """Get list of blocked devices"""
        return list(self.blocked_devices)


class VulnerabilityScanner:
    """Network vulnerability scanner"""
    
    def __init__(self):
        self.scan_results = {}
        
    async def scan_device_vulnerabilities(self, ip: str, ports: List[int] = None) -> dict:
        """Scan device for common vulnerabilities"""
        try:
            if not ports:
                ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5432, 3306]
            
            nm = nmap.PortScanner()
            
            # Comprehensive scan with version detection and vulnerability scripts
            port_str = ','.join(map(str, ports))
            scan_args = f'-sV -sC --script vuln -p{port_str} --version-intensity 9'
            
            print(f"Starting vulnerability scan for {ip}")
            nm.scan(ip, arguments=scan_args)
            
            vulnerabilities = []
            services = {}
            
            if ip in nm.all_hosts():
                for port in nm[ip].all_tcp():
                    port_info = nm[ip]['tcp'][port]
                    
                    # Extract service information
                    service = {
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
                    services[port] = service
                    
                    # Check for vulnerabilities in script results
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if any(vuln_keyword in script_output.lower() for vuln_keyword in 
                                  ['vulnerable', 'cve-', 'exploit', 'backdoor', 'weak']):
                                vulnerabilities.append({
                                    'port': port,
                                    'service': service['service'],
                                    'script': script_name,
                                    'finding': script_output,
                                    'severity': self._assess_vulnerability_severity(script_output)
                                })
            
            # Additional vulnerability checks
            vulnerabilities.extend(await self._check_common_vulnerabilities(ip, services))
            
            result = {
                'ip': ip,
                'scan_time': datetime.now().isoformat(),
                'services': services,
                'vulnerabilities': vulnerabilities,
                'risk_score': self._calculate_risk_score(vulnerabilities)
            }
            
            self.scan_results[ip] = result
            return result
            
        except Exception as e:
            return {
                'ip': ip,
                'error': str(e),
                'scan_time': datetime.now().isoformat(),
                'services': {},
                'vulnerabilities': [],
                'risk_score': 0
            }
    
    async def _check_common_vulnerabilities(self, ip: str, services: dict) -> List[dict]:
        """Check for common vulnerabilities based on services"""
        vulnerabilities = []
        
        for port, service in services.items():
            service_name = service['service'].lower()
            product = service.get('product', '').lower()
            version = service.get('version', '').lower()
            
            # Check for common vulnerable services
            if service_name == 'ssh' and port == 22:
                # Check for weak SSH configuration
                if await self._check_ssh_security(ip):
                    vulnerabilities.append({
                        'port': port,
                        'service': service_name,
                        'finding': 'SSH allows weak authentication methods',
                        'severity': 'medium',
                        'recommendation': 'Disable password authentication, use key-based auth'
                    })
            
            elif service_name == 'http' and port == 80:
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'finding': 'Unencrypted HTTP service detected',
                    'severity': 'low',
                    'recommendation': 'Use HTTPS instead of HTTP'
                })
            
            elif service_name == 'telnet':
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'finding': 'Insecure Telnet service detected',
                    'severity': 'high',
                    'recommendation': 'Replace Telnet with SSH'
                })
            
            elif service_name == 'ftp' and 'vsftpd 2.3.4' in product:
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'finding': 'Vulnerable FTP version with backdoor (CVE-2011-2523)',
                    'severity': 'critical',
                    'recommendation': 'Update FTP server immediately'
                })
            
            elif 'smb' in service_name or port in [139, 445]:
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'finding': 'SMB service detected - potential for EternalBlue exploitation',
                    'severity': 'high',
                    'recommendation': 'Ensure SMB is updated and properly configured'
                })
        
        return vulnerabilities
    
    async def _check_ssh_security(self, ip: str) -> bool:
        """Check SSH security configuration"""
        try:
            # Simple check - attempt to connect and see auth methods
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # This will fail but we can check supported auth methods
                ssh.connect(ip, port=22, username='nonexistent', password='invalid', timeout=5)
            except paramiko.AuthenticationException as e:
                # Check if password authentication is allowed
                return 'password' in str(e).lower()
            except:
                pass
            finally:
                ssh.close()
                
        except:
            pass
        
        return False
    
    def _assess_vulnerability_severity(self, finding: str) -> str:
        """Assess vulnerability severity based on finding"""
        finding_lower = finding.lower()
        
        if any(keyword in finding_lower for keyword in ['critical', 'remote code execution', 'backdoor']):
            return 'critical'
        elif any(keyword in finding_lower for keyword in ['high', 'exploit', 'privilege escalation']):
            return 'high'
        elif any(keyword in finding_lower for keyword in ['medium', 'information disclosure']):
            return 'medium'
        else:
            return 'low'
    
    def _calculate_risk_score(self, vulnerabilities: List[dict]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0
        
        severity_scores = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        total_score = sum(severity_scores.get(vuln.get('severity', 'low'), 3) for vuln in vulnerabilities)
        
        return min(100, total_score)
    
    def get_scan_results(self, ip: str = None) -> dict:
        """Get vulnerability scan results"""
        if ip:
            return self.scan_results.get(ip, {})
        return self.scan_results


# Global instances
security_monitor = SecurityMonitor()
network_defense = NetworkDefense()
vulnerability_scanner = VulnerabilityScanner()
