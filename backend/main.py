import asyncio
import json
from typing import Dict, List, Tuple
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import nmap
import psutil
import socket
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, conf, DHCP, BOOTP, ICMP, sr1
import netifaces
from threading import Thread, Event
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import platform
import re
import winreg
import requests
import websockets
import time
from pathlib import Path
from mac_vendor_lookup import MacLookup
import queue
import threading

# Initialize MAC lookup and thread pool
try:
    mac_lookup = MacLookup()
    thread_pool = ThreadPoolExecutor(max_workers=4)
    try:
        mac_lookup.update_vendors()
    except Exception as e:
        print(f"Warning: Could not update MAC vendor database: {e}")
except Exception as e:
    print(f"Warning: Could not initialize MAC vendor lookup: {e}")
    mac_lookup = None
    thread_pool = ThreadPoolExecutor(max_workers=4)

# Common OUI mappings for quick offline lookup
COMMON_OUIS = {
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:1B:21': 'VMware',
    '00:05:69': 'VMware',
    '00:03:FF': 'Microsoft',
    '00:12:5A': 'Microsoft',
    '00:15:5D': 'Microsoft (Hyper-V)',
    '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
    'FC:AA:14': 'Google',
    '00:1A:11': 'Google',
    '00:21:6A': 'Dell',
    '00:14:22': 'Dell',
    '00:1D:09': 'Dell',
    'B8:AC:6F': 'Dell',
    '3C:A8:2A': 'Dell',
    '00:13:72': 'Dell',
    '00:1E:C9': 'Dell',
    '00:26:B9': 'Dell',
    '00:1A:A0': 'Dell',
    '00:15:C5': 'Dell',
    '00:11:43': 'Dell',
    '00:90:27': 'Intel',
    '00:02:B3': 'Intel',
    '00:12:F0': 'Intel',
    '00:13:02': 'Intel',
    '00:13:20': 'Intel',
    '00:15:17': 'Intel',
    '00:16:E3': 'Intel',
    '00:19:D1': 'Intel',
    '00:1B:77': 'Intel',
    '00:1E:67': 'Intel',
    '00:21:70': 'Intel',
    '00:22:FB': 'Intel',
    '00:24:D7': 'Intel',
    '00:26:C7': 'Intel',
    '00:27:10': 'Intel',
    '04:CE:14': 'Intel',
    '08:11:96': 'Intel',
    '0C:8B:FD': 'Intel',
    '10:0B:A9': 'Intel',
    '18:03:73': 'Intel',
    '1C:87:2C': 'Intel',
    '20:16:B9': 'Intel',
    '24:4B:FE': 'Intel',
    '28:D2:44': 'Intel',
    '2C:59:E5': 'Intel',
    '34:13:E8': 'Intel',
    '38:2C:4A': 'Intel',
    '3C:A9:F4': 'Intel',
    '40:B0:34': 'Intel',
    '44:85:00': 'Intel',
    '48:45:20': 'Intel',
    '4C:79:6E': 'Intel',
    '50:46:5D': 'Intel',
    '54:E1:AD': 'Intel',
    '58:91:CF': 'Intel',
    '5C:E0:C5': 'Intel',
    '60:67:20': 'Intel',
    '64:00:6A': 'Intel',
    '68:05:CA': 'Intel',
    '6C:88:14': 'Intel',
    '70:1A:04': 'Intel',
    '74:E5:F9': 'Intel',
    '78:92:9C': 'Intel',
    '7C:7A:91': 'Intel',
    '80:19:34': 'Intel',
    '84:3A:4B': 'Intel',
    '88:75:56': 'Intel',
    '8C:A9:82': 'Intel',
    '90:E2:BA': 'Intel',
    '94:65:9C': 'Intel',
    '98:4F:EE': 'Intel',
    '9C:B6:D0': 'Intel',
    'A0:8C:FD': 'Intel',
    'A4:4C:C8': 'Intel',
    'A8:5E:45': 'Intel',
    'AC:7B:A1': 'Intel',
    'B0:35:9F': 'Intel',
    'B4:96:91': 'Intel',
    'B8:86:87': 'Intel',
    'BC:77:37': 'Intel',
    'C0:3F:D5': 'Intel',
    'C4:34:6B': 'Intel',
    'C8:5B:76': 'Intel',
    'CC:2F:71': 'Intel',
    'D0:50:99': 'Intel',
    'D4:BE:D9': 'Intel',
    'D8:CB:8A': 'Intel',
    'DC:53:60': 'Intel',
    'E0:DB:55': 'Intel',
    'E4:B3:18': 'Intel',
    'E8:39:35': 'Intel',
    'EC:A8:6B': 'Intel',
    'F0:76:1C': 'Intel',
    'F4:4D:30': 'Intel',
    'F8:63:3F': 'Intel',
    'FC:AA:14': 'Intel',
    '28:CF:E9': 'Apple',
    '00:03:93': 'Apple',
    '00:05:02': 'Apple',
    '00:0A:27': 'Apple',
    '00:0A:95': 'Apple',
    '00:0D:93': 'Apple',
    '00:11:24': 'Apple',
    '00:14:51': 'Apple',
    '00:16:CB': 'Apple',
    '00:17:F2': 'Apple',
    '00:19:E3': 'Apple',
    '00:1B:63': 'Apple',
    '00:1E:C2': 'Apple',
    '00:21:E9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:12': 'Apple',
    '00:23:32': 'Apple',
    '00:23:6C': 'Apple',
    '00:23:DF': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:4B': 'Apple',
    '00:25:BC': 'Apple',
    '00:26:08': 'Apple',
    '00:26:4A': 'Apple',
    '00:26:B0': 'Apple',
    '00:26:BB': 'Apple',
    '04:0C:CE': 'Apple',
    '04:15:52': 'Apple',
    '04:1E:64': 'Apple',
    '04:26:65': 'Apple',
    '04:48:9A': 'Apple',
    '04:4F:AA': 'Apple',
    '04:52:C7': 'Apple',
    '04:54:53': 'Apple',
    '04:69:F8': 'Apple',
    '04:DB:56': 'Apple',
    '04:E5:36': 'Apple',
    '04:F1:3E': 'Apple',
    '04:F7:E4': 'Apple',
    '08:6D:41': 'Apple',
    '08:74:02': 'Apple',
    '08:96:D7': 'Apple',
    '0C:3E:9F': 'Apple',
    '0C:4D:E9': 'Apple',
    '0C:71:5D': 'Apple',
    '0C:74:C2': 'Apple',
    '0C:77:1A': 'Apple',
    '0C:D2:92': 'Apple',
    '10:40:F3': 'Apple',
    '10:93:E9': 'Apple',
    '10:DD:B1': 'Apple',
    '14:10:9F': 'Apple',
    '14:20:5E': 'Apple',
    '14:5A:05': 'Apple',
    '14:7D:DA': 'Apple',
    '14:BD:61': 'Apple',
    '18:20:32': 'Apple',
    '18:34:51': 'Apple',
    '18:65:90': 'Apple',
    '18:AF:61': 'Apple',
    '18:E7:F4': 'Apple',
    '1C:1A:C0': 'Apple',
    '1C:36:BB': 'Apple',
    '1C:AB:A7': 'Apple',
    '1C:E6:2B': 'Apple',
    '20:3C:AE': 'Apple',
    '20:A2:E4': 'Apple',
    '20:C9:D0': 'Apple',
    '24:A0:74': 'Apple',
    '24:AB:81': 'Apple',
    '24:DA:9B': 'Apple',
    '24:F0:94': 'Apple',
    '24:F5:AA': 'Apple',
    '28:37:37': 'Apple',
    '28:6A:BA': 'Apple',
    '28:A0:2B': 'Apple',
    '28:B2:BD': 'Apple',
    '28:E0:2C': 'Apple',
    '2C:1F:23': 'Apple',
    '2C:36:F8': 'Apple',
    '2C:4D:54': 'Apple',
    '2C:54:CF': 'Apple',
    '2C:5F:F3': 'Apple',
    '2C:B4:3A': 'Apple',
    '2C:BE:08': 'Apple',
    '30:10:E4': 'Apple',
    '30:35:AD': 'Apple',
    '30:63:6B': 'Apple',
    '30:90:AB': 'Apple',
    '30:F7:C5': 'Apple',
    '34:15:9E': 'Apple',
    '34:36:3B': 'Apple',
    '34:51:8B': 'Apple',
    '34:A3:95': 'Apple',
    '34:C0:59': 'Apple',
    '34:E2:FD': 'Apple',
    '38:0F:4A': 'Apple',
    '38:48:4C': 'Apple',
    '38:89:DC': 'Apple',
    '38:B5:4D': 'Apple',
    '38:C9:86': 'Apple',
    '3C:15:C2': 'Apple',
    '3C:2E:F9': 'Apple',
    '3C:7C:3F': 'Apple',
    '3C:A6:F6': 'Apple',
    '40:31:3C': 'Apple',
    '40:33:1A': 'Apple',
    '40:4D:7F': 'Apple',
    '40:A6:D9': 'Apple',
    '40:B3:95': 'Apple',
    '40:CB:C0': 'Apple',
    '40:D3:2D': 'Apple',
    '44:00:10': 'Apple',
    '44:2A:60': 'Apple',
    '44:4C:0C': 'Apple',
    '44:D8:84': 'Apple',
    '44:FB:42': 'Apple',
    '48:43:7C': 'Apple',
    '48:60:BC': 'Apple',
    '48:74:6E': 'Apple',
    '48:A1:95': 'Apple',
    '48:BF:6B': 'Apple',
    '48:D7:05': 'Apple',
    '4C:3C:16': 'Apple',
    '4C:7C:5F': 'Apple',
    '4C:8D:79': 'Apple',
    '4C:B1:99': 'Apple',
    '50:32:37': 'Apple',
    '50:5A:65': 'Apple',
    '50:EA:D6': 'Apple',
    '54:26:96': 'Apple',
    '54:4E:90': 'Apple',
    '54:72:4F': 'Apple',
    '54:AE:27': 'Apple',
    '54:E4:3A': 'Apple',
    '58:40:4E': 'Apple',
    '58:55:CA': 'Apple',
    '58:B0:35': 'Apple',
    '5C:95:AE': 'Apple',
    '5C:96:9D': 'Apple',
    '5C:CF:7F': 'Apple',
    '5C:F9:38': 'Apple',
    '60:03:08': 'Apple',
    '60:33:4B': 'Apple',
    '60:5B:B4': 'Apple',
    '60:6C:66': 'Apple',
    '60:C5:47': 'Apple',
    '60:F4:45': 'Apple',
    '64:20:0C': 'Apple',
    '64:49:6F': 'Apple',
    '64:76:BA': 'Apple',
    '64:B0:A6': 'Apple',
    '64:E6:82': 'Apple',
    '68:5B:35': 'Apple',
    '68:96:7B': 'Apple',
    '68:AB:1E': 'Apple',
    '68:D9:3C': 'Apple',
    '6C:19:8F': 'Apple',
    '6C:3E:6D': 'Apple',
    '6C:40:08': 'Apple',
    '6C:4D:73': 'Apple',
    '6C:70:9F': 'Apple',
    '6C:8D:C1': 'Apple',
    '6C:94:66': 'Apple',
    '6C:AD:F8': 'Apple',
    '70:11:24': 'Apple',
    '70:48:0F': 'Apple',
    '70:56:81': 'Apple',
    '70:73:CB': 'Apple',
    '70:DE:E2': 'Apple',
    '70:EC:E4': 'Apple',
    '74:1B:B2': 'Apple',
    '74:2F:68': 'Apple',
    '74:E1:B6': 'Apple',
    '74:E2:F5': 'Apple',
    '78:31:C1': 'Apple',
    '78:4F:43': 'Apple',
    '78:7B:8A': 'Apple',
    '78:A3:E4': 'Apple',
    '78:CA:39': 'Apple',
    '78:FD:94': 'Apple',
    '7C:04:D0': 'Apple',
    '7C:11:BE': 'Apple',
    '7C:6D:62': 'Apple',
    '7C:C3:A1': 'Apple',
    '7C:D1:C3': 'Apple',
    '7C:F0:5F': 'Apple',
    '80:BE:05': 'Apple',
    '80:E6:50': 'Apple',
    '84:38:35': 'Apple',
    '84:78:AC': 'Apple',
    '84:FC:FE': 'Apple',
    '88:1F:A1': 'Apple',
    '88:53:2E': 'Apple',
    '88:63:DF': 'Apple',
    '88:66:5A': 'Apple',
    '88:AE:1D': 'Apple',
    '88:E8:7F': 'Apple',
    '8C:29:37': 'Apple',
    '8C:2D:AA': 'Apple',
    '8C:7C:92': 'Apple',
    '8C:8E:F2': 'Apple',
    '90:27:E4': 'Apple',
    '90:72:40': 'Apple',
    '90:B0:ED': 'Apple',
    '90:B2:1F': 'Apple',
    '94:E9:6A': 'Apple',
    '94:F6:A3': 'Apple',
    '98:03:9B': 'Apple',
    '98:0D:2E': 'Apple',
    '98:B8:E3': 'Apple',
    '98:FE:94': 'Apple',
    '9C:04:EB': 'Apple',
    '9C:20:7B': 'Apple',
    '9C:84:BF': 'Apple',
    '9C:93:4E': 'Apple',
    '9C:F3:87': 'Apple',
    'A0:99:9B': 'Apple',
    'A0:C5:89': 'Apple',
    'A0:D7:95': 'Apple',
    'A4:5E:60': 'Apple',
    'A4:83:E7': 'Apple',
    'A4:B1:97': 'Apple',
    'A4:C3:61': 'Apple',
    'A8:20:66': 'Apple',
    'A8:51:AB': 'Apple',
    'A8:60:B6': 'Apple',
    'A8:86:DD': 'Apple',
    'A8:88:08': 'Apple',
    'A8:96:75': 'Apple',
    'A8:BB:CF': 'Apple',
    'A8:FA:D8': 'Apple',
    'AC:1F:74': 'Apple',
    'AC:29:3A': 'Apple',
    'AC:3C:0B': 'Apple',
    'AC:61:EA': 'Apple',
    'AC:87:A3': 'Apple',
    'AC:BC:32': 'Apple',
    'AC:CF:23': 'Apple',
    'AC:F7:F3': 'Apple',
    'B0:09:DA': 'Apple',
    'B0:34:95': 'Apple',
    'B0:48:7A': 'Apple',
    'B0:65:BD': 'Apple',
    'B0:CA:68': 'Apple',
    'B4:18:D1': 'Apple',
    'B4:8B:19': 'Apple',
    'B4:9C:DF': 'Apple',
    'B4:F0:AB': 'Apple',
    'B4:F6:1C': 'Apple',
    'B8:09:8A': 'Apple',
    'B8:17:C2': 'Apple',
    'B8:27:EB': 'Apple',
    'B8:53:AC': 'Apple',
    'B8:63:BC': 'Apple',
    'B8:78:26': 'Apple',
    'B8:8D:12': 'Apple',
    'B8:C7:5D': 'Apple',
    'B8:E8:56': 'Apple',
    'B8:F6:B1': 'Apple',
    'B8:FF:61': 'Apple',
    'BC:3B:AF': 'Apple',
    'BC:52:B7': 'Apple',
    'BC:67:1C': 'Apple',
    'BC:6C:21': 'Apple',
    'BC:92:6B': 'Apple',
    'BC:9F:EF': 'Apple',
    'BC:F5:AC': 'Apple',
    'C0:25:5C': 'Apple',
    'C0:6B:8E': 'Apple',
    'C0:7C:D1': 'Apple',
    'C0:CE:CD': 'Apple',
    'C0:D0:12': 'Apple',
    'C4:2C:03': 'Apple',
    'C4:B3:01': 'Apple',
    'C8:21:58': 'Apple',
    'C8:2A:14': 'Apple',
    'C8:33:4B': 'Apple',
    'C8:69:CD': 'Apple',
    'C8:BC:C8': 'Apple',
    'C8:E0:EB': 'Apple',
    'C8:F6:50': 'Apple',
    'CC:08:8D': 'Apple',
    'CC:20:E8': 'Apple',
    'CC:25:EF': 'Apple',
    'CC:29:F5': 'Apple',
    'CC:2D:8C': 'Apple',
    'CC:78:AB': 'Apple',
    'CC:C7:60': 'Apple',
    'D0:03:4B': 'Apple',
    'D0:23:DB': 'Apple',
    'D0:33:11': 'Apple',
    'D0:81:7A': 'Apple',
    'D0:A6:37': 'Apple',
    'D4:61:DA': 'Apple',
    'D4:9A:20': 'Apple',
    'D4:DC:CD': 'Apple',
    'D4:F4:6F': 'Apple',
    'D8:1D:72': 'Apple',
    'D8:30:62': 'Apple',
    'D8:96:95': 'Apple',
    'D8:A2:5E': 'Apple',
    'D8:BB:2C': 'Apple',
    'DC:0C:5C': 'Apple',
    'DC:2B:2A': 'Apple',
    'DC:37:45': 'Apple',
    'DC:3E:51': 'Apple',
    'DC:56:E7': 'Apple',
    'DC:86:D8': 'Apple',
    'DC:A4:CA': 'Apple',
    'DC:A9:04': 'Apple',
    'DC:B4:C4': 'Apple',
    'DC:F8:56': 'Apple',
    'E0:33:8E': 'Apple',
    'E0:88:5D': 'Apple',
    'E0:AC:CB': 'Apple',
    'E0:B5:2D': 'Apple',
    'E0:C9:7A': 'Apple',
    'E0:F8:47': 'Apple',
    'E4:8B:7F': 'Apple',
    'E4:C6:3D': 'Apple',
    'E4:CE:8F': 'Apple',
    'E8:04:0B': 'Apple',
    'E8:06:88': 'Apple',
    'E8:2A:EA': 'Apple',
    'E8:40:F2': 'Apple',
    'E8:80:2E': 'Apple',
    'E8:B2:AC': 'Apple',
    'EC:35:86': 'Apple',
    'EC:8A:4C': 'Apple',
    'F0:18:98': 'Apple',
    'F0:1D:BC': 'Apple',
    'F0:2F:74': 'Apple',
    'F0:61:9D': 'Apple',
    'F0:98:9D': 'Apple',
    'F0:B4:79': 'Apple',
    'F0:C1:F1': 'Apple',
    'F0:CB:A1': 'Apple',
    'F0:DB:E2': 'Apple',
    'F0:DC:E2': 'Apple',
    'F0:E5:7B': 'Apple',
    'F4:0F:24': 'Apple',
    'F4:31:C3': 'Apple',
    'F4:37:B7': 'Apple',
    'F4:5C:89': 'Apple',
    'F4:7F:35': 'Apple',
    'F4:8E:38': 'Apple',
    'F4:F1:5A': 'Apple',
    'F4:F9:51': 'Apple',
    'F8:01:13': 'Apple',
    'F8:1E:DF': 'Apple',
    'F8:2D:7C': 'Apple',
    'F8:4F:AD': 'Apple',
    'F8:A9:D0': 'Apple',
    'F8:E9:4E': 'Apple',
    'F8:F2:1E': 'Apple',
    'FC:25:3F': 'Apple',
    'FC:E9:98': 'Apple',
    '00:50:F2': 'Samsung',
    '00:12:FB': 'Samsung',
    '00:13:77': 'Samsung',
    '00:15:99': 'Samsung',
    '00:16:32': 'Samsung',
    '00:17:C9': 'Samsung',
    '00:1B:98': 'Samsung',
    '00:1C:43': 'Samsung',
    '00:1D:25': 'Samsung',
    '00:1E:7D': 'Samsung',
    '00:1F:CC': 'Samsung',
    '00:21:19': 'Samsung',
    '00:23:39': 'Samsung',
    '00:24:54': 'Samsung',
    '00:26:37': 'Samsung',
    '04:18:D6': 'Samsung',
    '04:FE:7F': 'Samsung',
    '08:08:C2': 'Samsung',
    '08:37:3D': 'Samsung',
    '08:EC:A9': 'Samsung',
    '0C:14:20': 'Samsung',
    '0C:89:10': 'Samsung',
    '10:1D:C0': 'Samsung',
    '10:30:47': 'Samsung',
    '10:77:B1': 'Samsung',
    '10:BD:18': 'Samsung',
    '14:13:33': 'Samsung',
    '14:49:E0': 'Samsung',
    '14:7F:D2': 'Samsung',
    '14:A5:1A': 'Samsung',
    '18:22:7E': 'Samsung',
    '18:3A:2D': 'Samsung',
    '18:44:4F': 'Samsung',
    '18:4F:32': 'Samsung',
    '18:5E:0F': 'Samsung',
    '18:68:CB': 'Samsung',
    '18:CF:5E': 'Samsung',
    '1C:5A:3E': 'Samsung',
    '1C:62:B8': 'Samsung',
    '20:13:E0': 'Samsung',
    '20:64:32': 'Samsung',
    '24:4B:81': 'Samsung',
    '24:5A:2C': 'Samsung',
    '28:39:5E': 'Samsung',
    '28:E3:47': 'Samsung',
    '2C:44:01': 'Samsung',
    '2C:8A:72': 'Samsung',
    '2C:3B:70': 'Samsung', 
    '30:07:4D': 'Samsung',
    '30:19:66': 'Samsung',
    '30:85:A9': 'Samsung',
    '34:AA:8B': 'Samsung',
    '34:BE:00': 'Samsung',
    '34:E8:94': 'Samsung',
    '38:AA:3C': 'Samsung',
    '38:E7:D8': 'Samsung',
    '3C:5A:B4': 'Samsung',
    '3C:8B:FE': 'Samsung',
    '40:0E:85': 'Samsung',
    '40:4E:36': 'Samsung',
    '40:B8:9A': 'Samsung',
    '44:5E:F3': 'Samsung',
    '44:D8:8A': 'Samsung',
    '48:5A:3F': 'Samsung',
    '4C:3C:16': 'Samsung',
    '4C:66:41': 'Samsung',
    '4C:BC:A5': 'Samsung',
    '50:01:BB': 'Samsung',
    '50:32:75': 'Samsung',
    '50:CC:F8': 'Samsung',
    '54:88:0E': 'Samsung',
    '58:50:E6': 'Samsung',
    '5C:0A:5B': 'Samsung',
    '5C:51:88': 'Samsung',
    '5C:F6:DC': 'Samsung',
    '60:21:C0': 'Samsung',
    '60:A1:0A': 'Samsung',
    '68:EB:C5': 'Samsung',
    '6C:2F:2C': 'Samsung',
    '6C:83:36': 'Samsung',
    '78:1F:DB': 'Samsung',
    '78:25:AD': 'Samsung',
    '78:47:1D': 'Samsung',
    '78:52:1A': 'Samsung',
    '78:59:5E': 'Samsung',
    '78:67:D5': 'Samsung',
    '78:D6:F0': 'Samsung',
    '7C:61:93': 'Samsung',
    '7C:A2:3E': 'Samsung',
    '80:57:19': 'Samsung',
    '80:7A:BF': 'Samsung',
    '84:25:3F': 'Samsung',
    '84:38:38': 'Samsung',
    '84:A4:66': 'Samsung',
    '88:32:9B': 'Samsung',
    '8C:77:12': 'Samsung',
    '90:18:7C': 'Samsung',
    '94:35:0A': 'Samsung',
    '94:44:44': 'Samsung',
    '9C:02:98': 'Samsung',
    '9C:3A:AF': 'Samsung',
    '9C:65:B0': 'Samsung',
    'A0:0B:BA': 'Samsung',
    'A0:75:91': 'Samsung',
    'A0:82:1F': 'Samsung',
    'A0:AF:BD': 'Samsung',
    'A4:14:37': 'Samsung',
    'A4:EB:D3': 'Samsung',
    'A8:F2:74': 'Samsung',
    'AC:5F:3E': 'Samsung',
    'B0:EC:71': 'Samsung',
    'B4:62:93': 'Samsung',
    'B4:74:9F': 'Samsung',
    'B8:5A:F7': 'Samsung',
    'BC:20:A4': 'Samsung',
    'BC:72:B1': 'Samsung',
    'BC:85:1F': 'Samsung',
    'BC:F5:AC': 'Samsung',
    'C0:BD:D1': 'Samsung',
    'C4:57:6E': 'Samsung',
    'C8:1E:E7': 'Samsung',
    'C8:3A:35': 'Samsung',
    'C8:BA:94': 'Samsung',
    'CC:07:AB': 'Samsung',
    'D0:17:C2': 'Samsung',
    'D0:22:BE': 'Samsung',
    'D0:59:E4': 'Samsung',
    'D4:87:D8': 'Samsung',
    'D4:E8:B2': 'Samsung',
    'D8:31:CF': 'Samsung',
    'D8:90:E8': 'Samsung',
    'DC:71:96': 'Samsung',
    'E0:91:F5': 'Samsung',
    'E4:40:E2': 'Samsung',
    'E8:50:8B': 'Samsung',
    'E8:E5:D6': 'Samsung',
    'EC:1F:72': 'Samsung',
    'EC:9B:F3': 'Samsung',
    'F0:25:B7': 'Samsung',
    'F4:0E:01': 'Samsung',
    'F4:73:35': 'Samsung',
    'F4:7B:5E': 'Samsung',
    'F8:04:2E': 'Samsung',
    'F8:16:54': 'Samsung',
    'F8:A9:D0': 'Samsung',
    'FC:00:12': 'Samsung',
    'FC:A1:3E': 'Samsung',
    'FC:C2:DE': 'Samsung'
}

class VendorLookupService:
    """Background service for vendor lookups to avoid blocking the main event loop"""
    
    def __init__(self):
        self.lookup_queue = queue.Queue()
        self.result_callbacks = {}
        self.running = False
        self.worker_thread = None
        self.mac_lookup = None
        
        # Initialize MAC lookup in this thread
        try:
            self.mac_lookup = MacLookup()
            self.mac_lookup.update_vendors()
            print("Vendor lookup service initialized successfully")
        except Exception as e:
            print(f"Warning: Could not initialize MAC vendor lookup in service: {e}")
    
    def start(self):
        """Start the background vendor lookup service"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        print("Vendor lookup service started")
    
    def stop(self):
        """Stop the background vendor lookup service"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
    
    def lookup_vendor_async(self, mac: str, callback=None) -> str:
        """Queue a vendor lookup request"""
        request_id = f"{mac}_{time.time()}"
        if callback:
            self.result_callbacks[request_id] = callback
        
        self.lookup_queue.put({
            'id': request_id,
            'mac': mac,
            'has_callback': callback is not None
        })
        return request_id
    
    def _worker_loop(self):
        """Main worker loop for processing vendor lookups"""
        while self.running:
            try:
                # Get request from queue with timeout
                request = self.lookup_queue.get(timeout=1)
                
                mac = request['mac']
                request_id = request['id']
                
                # Perform the lookup
                vendor, device_type = self._perform_lookup(mac)
                
                # Call callback if provided
                if request['has_callback'] and request_id in self.result_callbacks:
                    try:
                        self.result_callbacks[request_id](mac, vendor, device_type)
                        del self.result_callbacks[request_id]
                    except Exception as e:
                        print(f"Error in vendor lookup callback: {e}")
                
                self.lookup_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in vendor lookup worker: {e}")
    
    def _perform_lookup(self, mac: str) -> tuple:
        """Perform the actual vendor lookup"""
        vendor_name = "Unknown"
        device_type = "Unknown"
        
        try:
            # Ensure MAC format is consistent
            clean_mac = mac.replace('-', ':').upper()
            
            # Try primary lookup first
            if self.mac_lookup is not None:
                try:
                    vendor_name = str(self.mac_lookup.lookup(clean_mac))
                    print(f"Vendor service found: {clean_mac} -> {vendor_name}")
                except Exception as e:
                    print(f"Primary lookup failed for {clean_mac}: {e}")
            
            # If primary failed, try fallback methods
            if vendor_name == "Unknown":
                vendor_name = self._oui_fallback_lookup(clean_mac)
            
            # Determine device type based on vendor patterns
            if vendor_name != "Unknown":
                vendor_name_lower = vendor_name.lower()
                for type_name, patterns in DEVICE_PATTERNS.items():
                    if any(pattern in vendor_name_lower for pattern in patterns):
                        device_type = type_name
                        break
            
            return vendor_name, device_type
            
        except Exception as e:
            print(f"Error in vendor lookup for {mac}: {e}")
            return "Unknown", "Unknown"
    
    def _oui_fallback_lookup(self, mac: str) -> str:
        """Fallback OUI vendor lookup"""
        try:
            # First try common OUI database
            oui = mac.replace(':', '').replace('-', '').replace('.', '').upper()[:6]
            formatted_oui = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"
            
            if formatted_oui in COMMON_OUIS:
                print(f"Found vendor in common OUI database: {COMMON_OUIS[formatted_oui]}")
                return COMMON_OUIS[formatted_oui]
            
            # Try online API with timeout
            try:
                response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
                if response.status_code == 200:
                    vendor = response.text.strip()
                    if vendor and not vendor.lower().startswith('not found') and vendor != "N/A":
                        print(f"Found vendor via API: {vendor}")
                        return vendor
            except Exception:
                pass  # Silently fail and continue
            
        except Exception as e:
            print(f"OUI fallback lookup failed for {mac}: {e}")
        
        return "Unknown"

# Initialize the vendor lookup service
vendor_service = VendorLookupService()

try:
    mac_lookup.update_vendors()
except Exception as e:
    print(f"Warning: Could not update MAC vendor database: {e}")

# Enhanced device type patterns
DEVICE_PATTERNS = {
    'Mobile Device': [
        'apple', 'iphone', 'ipad', 'samsung mobile', 'xiaomi', 'oneplus', 'oppo', 
        'vivo', 'huawei', 'honor', 'realme', 'motorola', 'lg electronics mobile',
        'android', 'mobile'
    ],
    'Smart TV': [
        'samsung electronics tv', 'lg tv', 'vizio', 'sony tv', 'tcl', 'hisense', 
        'roku', 'philips tv', 'sharp tv', 'panasonic tv', 'smarttv', 'appletv'
    ],
    'Gaming Console': [
        'nintendo', 'sony interactive entertainment', 'microsoft xbox', 'playstation',
        'nintendo switch', 'xbox', 'ps4', 'ps5'
    ],
    'IoT Device': [
        'nest', 'ring', 'ecobee', 'philips lighting', 'arlo', 'amazon technologies',
        'google home', 'sonos', 'belkin', 'smartthings', 'hue', 'zigbee', 'zwave'
    ],
    'Network Device': [
        'cisco', 'netgear', 'tp-link', 'd-link', 'ubiquiti', 'mikrotik', 'aruba',
        'ruckus', 'juniper', 'fortinet', 'palo alto', 'router', 'switch', 'ap'
    ]
}

# Common ports for device identification
DEVICE_PORTS = {
    'Mobile Device': [62078, 62078, 5353, 137, 138],  # iOS & Android common ports
    'Smart TV': [3000, 3001, 8008, 8009, 7000],  # Smart TV ports
    'Gaming Console': [3074, 3075, 3076, 1935],  # Gaming ports
    'IoT Device': [8883, 1883, 80, 443, 8080],  # IoT common ports
    'Computer': [445, 139, 135, 22, 3389]  # Common computer ports
}

# DHCP Fingerprinting patterns
DHCP_SIGNATURES = {
    'Windows': ['MSFT', 'Windows'],
    'Linux': ['Linux', 'Ubuntu', 'Debian', 'Red Hat'],
    'Mobile Device': ['iPhone', 'iPad', 'Android', 'Samsung'],
    'IoT Device': ['ESP', 'Raspberry', 'Docker', 'Container'],
    'Smart TV': ['Samsung TV', 'LG TV', 'Roku', 'Apple TV'],
    'Gaming Console': ['Xbox', 'PlayStation', 'Nintendo']
}

# TTL signatures for OS detection
TTL_SIGNATURES = {
    64: ['Linux', 'Unix', 'IoT Device'],
    128: ['Windows'],
    255: ['Network Device', 'Router'],
    32: ['Windows Mobile'],
    48: ['Mobile Device']
}

# Service banner patterns
SERVICE_SIGNATURES = {
    'Windows': ['microsoft', 'windows', 'iis'],
    'Linux': ['ubuntu', 'debian', 'centos', 'red hat', 'apache'],
    'Mobile Device': ['mobile', 'android', 'ios'],
    'IoT Device': ['busybox', 'embedded', 'router']
}

# Enhanced port signatures for device type detection
PORT_SIGNATURES = {
    'Mobile Device': {
        'required': [62078],  # iOS sync
        'optional': [5353, 137, 138, 1234, 5000],  # mDNS, NetBIOS, common mobile apps
        'weight': 0.7
    },
    'Smart TV': {
        'required': [8008, 8009],  # Chromecast
        'optional': [3000, 3001, 7000, 9080, 9197],  # Common smart TV ports
        'weight': 0.8
    },
    'Gaming Console': {
        'required': [3074],  # Xbox Live
        'optional': [3075, 3076, 1935, 3478, 3479, 3480],  # PSN, Nintendo
        'weight': 0.9
    },
    'IoT Device': {
        'required': [8883, 1883],  # MQTT
        'optional': [80, 443, 8080, 8081, 2525],  # Web interfaces
        'weight': 0.6
    },
    'Computer': {
        'required': [445, 139],  # SMB
        'optional': [135, 22, 3389, 80, 443],  # RDP, SSH, Web
        'weight': 0.8
    },
    'Network Device': {
        'required': [23, 22],  # Telnet, SSH
        'optional': [80, 443, 161, 162, 514, 2000],  # SNMP, Syslog
        'weight': 0.9
    }
}

def get_oui_vendor_fallback(mac: str) -> str:
    """Fallback OUI vendor lookup using multiple methods"""
    try:
        # First try common OUI database
        oui = mac.replace(':', '').replace('-', '').replace('.', '').upper()[:6]
        formatted_oui = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"
        
        if formatted_oui in COMMON_OUIS:
            print(f"Found vendor in common OUI database: {COMMON_OUIS[formatted_oui]}")
            return COMMON_OUIS[formatted_oui]
        
        # Try online API as second fallback (with reduced timeout)
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and not vendor.lower().startswith('not found') and vendor != "N/A":
                    print(f"Found vendor via API: {vendor}")
                    return vendor
        except Exception as api_error:
            print(f"API lookup failed: {api_error}")
        
        # Try IEEE OUI database as third fallback
        response = requests.get(f"http://standards-oui.ieee.org/oui.txt", timeout=5)
        if response.status_code == 200:
            oui_data = response.text
            # Search for the OUI in the file
            for line in oui_data.split('\n'):
                if oui.upper() in line and '(hex)' in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        return parts[2].strip()
        
    except Exception as e:
        print(f"OUI fallback lookup failed for {mac}: {e}")
    
    return "Unknown"

def get_vendor_info_sync(mac: str) -> tuple:
    """Get vendor information from MAC address synchronously with multiple fallbacks"""
    vendor_name = "Unknown"
    device_type = "Unknown"
    
    try:
        # Ensure MAC format is consistent
        clean_mac = mac.replace('-', ':').upper()
        
        # Quick check in common OUI database first (fastest)
        oui = clean_mac.replace(':', '').replace('-', '').replace('.', '').upper()[:6]
        formatted_oui = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"
        
        if formatted_oui in COMMON_OUIS:
            vendor_name = COMMON_OUIS[formatted_oui]
            print(f"Found vendor in common OUI database: {vendor_name}")
        else:
            # For unknown vendors, just return Unknown immediately to avoid blocking
            # The vendor service will handle the lookup in background
            print(f"Vendor not in common database for {clean_mac}, will be looked up in background")
        
        # Determine device type based on vendor patterns
        if vendor_name != "Unknown":
            vendor_name_lower = vendor_name.lower()
            for type_name, patterns in DEVICE_PATTERNS.items():
                if any(pattern in vendor_name_lower for pattern in patterns):
                    device_type = type_name
                    break
        
        return vendor_name, device_type
        
    except Exception as e:
        print(f"Error in get_vendor_info_sync for {mac}: {e}")
        return "Unknown", "Unknown"

def request_vendor_lookup_async(mac: str, update_callback=None):
    """Request an async vendor lookup that won't block the main thread"""
    return vendor_service.lookup_vendor_async(mac, update_callback)

def analyze_ttl(ttl: int) -> str:
    """Analyze TTL value to guess OS/device type"""
    # Find the closest TTL base value
    base_ttl = min(TTL_SIGNATURES.keys(), key=lambda x: abs(x - ttl))
    
    # If TTL is within reasonable range of base value (accounting for hops)
    if abs(base_ttl - ttl) <= 5:
        return TTL_SIGNATURES[base_ttl][0]
    return "Unknown"

def analyze_dhcp_fingerprint(packet) -> str:
    """Analyze DHCP packets for vendor class identifier"""
    try:
        if DHCP in packet:
            options = packet[DHCP].options
            for option in options:
                if isinstance(option, tuple) and option[0] == 'vendor_class_id':
                    vendor_id = option[1].decode('utf-8', errors='ignore').lower()
                    for device_type, patterns in DHCP_SIGNATURES.items():
                        if any(pattern.lower() in vendor_id for pattern in patterns):
                            return device_type
    except Exception as e:
        print(f"Error analyzing DHCP fingerprint: {e}")
    return "Unknown"

def analyze_service_banner(ip: str, ports: list) -> str:
    """Analyze service banners for device type hints"""
    try:
        nm = nmap.PortScanner()
        # Quick service scan on common ports
        nm.scan(ip, arguments=f'-sV -p{",".join(map(str, ports))} --version-intensity 5')
        
        if ip in nm.all_hosts():
            for port in nm[ip].all_tcp():
                if 'product' in nm[ip]['tcp'][port]:
                    banner = nm[ip]['tcp'][port]['product'].lower()
                    for device_type, patterns in SERVICE_SIGNATURES.items():
                        if any(pattern in banner for pattern in patterns):
                            return device_type
    except Exception as e:
        print(f"Error analyzing service banner: {e}")
    return "Unknown"

def identify_device_type_threaded(mac: str, hostname: str, ports: set, ip: str = None) -> tuple:
    """Enhanced device type identification using multiple methods"""
    try:
        # Start with vendor lookup
        vendor, device_type = get_vendor_info_sync(mac)
        
        # If device type is still unknown, try other methods
        if device_type == "Unknown":
            # Check hostname patterns
            hostname_lower = hostname.lower()
            for type_name, patterns in DEVICE_PATTERNS.items():
                if any(pattern in hostname_lower for pattern in patterns):
                    device_type = type_name
                    break
        
        # If still unknown and we have ports, check port patterns
        if device_type == "Unknown" and ports:
            for type_name, device_ports in DEVICE_PORTS.items():
                if any(port in ports for port in device_ports):
                    device_type = type_name
                    break
        
        # If we have an IP, try service banner analysis
        if device_type == "Unknown" and ip and ports:
            device_type = analyze_service_banner(ip, list(ports)[:10])  # Limit to first 10 ports
        
        # Additional heuristics based on port characteristics
        if device_type == "Unknown":
            if any(port in ports for port in [62078, 5353]):  # iOS/Android ports
                device_type = "Mobile Device"
            elif len(ports) < 5 and all(port in [80, 443, 8080, 1883, 8883] for port in ports):
                device_type = "IoT Device"
            elif len(ports) > 10 and any(port in [22, 445, 139] for port in ports):
                device_type = "Computer"
        
        return vendor, device_type
    except Exception as e:
        print(f"Error in identify_device_type for MAC {mac}: {e}")
        return "Unknown", "Unknown"

def identify_device_type_sync(mac: str, hostname: str, ports: set, ip: str = None) -> tuple:
    """Synchronous device type identification - safe for any context"""
    try:
        # Use only sync vendor lookup
        vendor, device_type = get_vendor_info_sync(mac)
        
        # If device type is still unknown, try other methods
        if device_type == "Unknown":
            # Check hostname patterns
            hostname_lower = hostname.lower()
            for type_name, patterns in DEVICE_PATTERNS.items():
                if any(pattern in hostname_lower for pattern in patterns):
                    device_type = type_name
                    break
        
        # If still unknown and we have ports, check port patterns
        if device_type == "Unknown" and ports:
            for type_name, device_ports in DEVICE_PORTS.items():
                if any(port in ports for port in device_ports):
                    device_type = type_name
                    break
        
        # Additional heuristics based on port characteristics
        if device_type == "Unknown":
            if any(port in ports for port in [62078, 5353]):  # iOS/Android ports
                device_type = "Mobile Device"
            elif len(ports) < 5 and all(port in [80, 443, 8080, 1883, 8883] for port in ports):
                device_type = "IoT Device"
            elif len(ports) > 10 and any(port in [22, 445, 139] for port in ports):
                device_type = "Computer"
        
        return vendor, device_type
        
    except Exception as e:
        print(f"Error in identify_device_type_sync for MAC {mac}: {e}")
        return "Unknown", "Unknown"

app = FastAPI(title="NetSentinel API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store connected clients
connected_clients: List[WebSocket] = []
# Store device history
device_history: Dict[str, dict] = {}
# Store live packet data
packet_stats = defaultdict(lambda: {
    'packets': 0,
    'bytes': 0,
    'last_seen': None,
    'protocols': set(),
    'ports': set(),
    'dns_queries': set()  # Track DNS queries for better device identification
})

# Global flags
is_sniffing = False
sniffer_thread = None
auto_scan = False
mdns_thread = None
stop_scan_event = Event()

# Add traffic monitoring thresholds
TRAFFIC_THRESHOLDS = {
    'high_traffic': 1000000,  # 1MB/s
    'suspicious_ports': [22, 23, 3389, 445],  # SSH, Telnet, RDP, SMB
    'scan_threshold': 100,  # Number of different ports accessed in short time
    'connection_burst': 50,  # Number of connections in 1 minute
}

# Add alert history
alert_history = []

def get_windows_interfaces():
    """Get Windows interface information"""
    interfaces = {}
    
    # Get network interfaces from netifaces
    for interface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                # Try to get the friendly name from Windows registry
                friendly_name = None
                if platform.system() == "Windows" and re.match(r'{[\w-]+}', interface):
                    try:
                        key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path + "\\" + interface + "\\Connection", 0, winreg.KEY_READ) as key:
                            friendly_name = winreg.QueryValueEx(key, "Name")[0]
                    except:
                        friendly_name = interface

                interfaces[interface] = {
                    'name': friendly_name or interface,
                    'description': '',
                    'ip': ip_info.get('addr'),
                    'netmask': ip_info.get('netmask')
                }
        except Exception as e:
            print(f"Error processing interface {interface}: {str(e)}")
            continue
    
    return interfaces

def get_interface_name(guid: str) -> str:
    """Convert Windows interface GUID to interface name"""
    try:
        if platform.system() == "Windows":
            # Try to get from Windows registry
            try:
                key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path + "\\" + guid + "\\Connection", 0, winreg.KEY_READ) as key:
                    return winreg.QueryValueEx(key, "Name")[0]
            except:
                # If registry lookup fails, try interfaces list
                interfaces = get_windows_interfaces()
                if guid in interfaces:
                    return interfaces[guid]['name']
    except Exception as e:
        print(f"Error getting interface name: {str(e)}")
    return guid

def get_default_gateway():
    """Get the default gateway interface and IP"""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            interface = gateways['default'][netifaces.AF_INET][1]
            print(f"Found default gateway: {gateway_ip} on interface {interface}")
            
            # Get the friendly name for Windows interfaces
            if platform.system() == "Windows" and re.match(r'{[\w-]+}', interface):
                friendly_name = get_interface_name(interface)
                print(f"Using interface friendly name: {friendly_name}")
                return interface, gateway_ip, friendly_name
            
            return interface, gateway_ip, interface
    except Exception as e:
        print(f"Error getting default gateway: {str(e)}")
    return None, None, None

def packet_callback(packet):
    """Enhanced packet processing with additional device detection methods"""
    try:
        # Extract IP addresses and MAC addresses
        if ARP in packet:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            dst_mac = packet[ARP].hwdst
            dst_ip = packet[ARP].pdst
            
            update_device_info(src_ip, src_mac)
            if dst_mac != "00:00:00:00:00:00":
                update_device_info(dst_ip, dst_mac)
                
        elif IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            
            # Store TTL for OS detection
            if src_ip in packet_stats:
                packet_stats[src_ip]['ttl'] = ttl
            
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                update_device_info(src_ip, src_mac)
                update_device_info(dst_ip, dst_mac)
            
            # Update packet statistics
            packet_stats[src_ip]['packets'] += 1
            packet_stats[src_ip]['bytes'] += len(packet)
            packet_stats[src_ip]['last_seen'] = datetime.now()
            
            # Analyze DHCP packets
            if DHCP in packet:
                device_type = analyze_dhcp_fingerprint(packet)
                if device_type != "Unknown" and src_mac in device_history:
                    device_history[src_mac]['device_type'] = device_type
            
            # Track protocols and ports
            if TCP in packet or UDP in packet:
                proto = TCP if TCP in packet else UDP
                sport = packet[proto].sport
                dport = packet[proto].dport
                packet_stats[src_ip]['ports'].add(sport)
                packet_stats[dst_ip]['ports'].add(dport)
                
            # Process DNS packets
            if DNS in packet:
                process_dns_packet(packet, src_ip, dst_ip)
                
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

def process_dns_packet(packet, src_ip, dst_ip):
    """Process DNS and mDNS packets for device discovery"""
    try:
        if packet.haslayer(DNS):
            # Process queries
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8').lower()
                packet_stats[src_ip]['dns_queries'].add(query)
                
                # Look for device-specific patterns in DNS queries
                if any(pattern in query for pattern in [
                    'apple-mobile', 'iphone', 'ipad', 'android', 
                    'smarttv', 'roku', 'firetv', 'chromecast',
                    'playstation', 'xbox', 'nintendo',
                    'philips-hue', 'nest', 'iot'
                ]):
                    # Update device type based on DNS query
                    if src_ip in device_history:
                        device = device_history[src_ip]
                        if 'mobile' in query:
                            device['device_type'] = 'Mobile Device'
                        elif any(tv in query for tv in ['smarttv', 'roku', 'firetv']):
                            device['device_type'] = 'Smart TV'
                        elif any(game in query for game in ['playstation', 'xbox', 'nintendo']):
                            device['device_type'] = 'Gaming Console'
                        elif any(iot in query for iot in ['philips-hue', 'nest', 'iot']):
                            device['device_type'] = 'IoT Device'
            
            # Process responses
            if packet.haslayer(DNSRR):
                answer = packet[DNSRR].rdata
                if isinstance(answer, bytes):
                    answer = answer.decode('utf-8')
                # Update device hostname if found
                if src_ip in device_history:
                    device_history[src_ip]['hostname'] = answer.rstrip('.')
                    
    except Exception as e:
        print(f"Error processing DNS packet: {str(e)}")

def generate_alert(device_mac: str, alert_type: str, severity: str, details: str):
    """Generate and store an alert"""
    alert = {
        'timestamp': datetime.now().isoformat(),
        'device_mac': device_mac,
        'device_name': device_history.get(device_mac, {}).get('hostname', 'Unknown'),
        'type': alert_type,
        'severity': severity,
        'details': details
    }
    alert_history.append(alert)
    # Keep only last 1000 alerts
    if len(alert_history) > 1000:
        alert_history.pop(0)
    return alert

def check_device_alerts(device_mac: str, device_data: dict):
    """Check for suspicious activity and generate alerts"""
    alerts = []
    
    # Check traffic volume
    if device_data['traffic']['bytes'] > TRAFFIC_THRESHOLDS['high_traffic']:
        alerts.append(generate_alert(
            device_mac,
            'High Traffic',
            'warning',
            f"Device is generating high traffic: {device_data['traffic']['bytes']} bytes"
        ))
    
    # Check suspicious ports
    device_ports = set(port['port'] for port in device_data.get('ports', []))
    suspicious_ports = device_ports.intersection(TRAFFIC_THRESHOLDS['suspicious_ports'])
    if suspicious_ports:
        alerts.append(generate_alert(
            device_mac,
            'Suspicious Ports',
            'high',
            f"Device has suspicious ports open: {list(suspicious_ports)}"
        ))
    
    # Check for port scanning behavior
    if len(device_ports) > TRAFFIC_THRESHOLDS['scan_threshold']:
        alerts.append(generate_alert(
            device_mac,
            'Port Scanning',
            'high',
            f"Device accessed unusually high number of ports: {len(device_ports)}"
        ))
    
    return alerts

def update_device_info(ip: str, mac: str, skip_vendor_lookup: bool = False):
    """Update device information based on captured packets"""
    try:
        if mac not in device_history:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            
            ports = set()
            if ip in packet_stats:
                ports = packet_stats[ip]['ports']
            
            device_history[mac] = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'vendor': "Unknown",
                'device_type': "Unknown",
                'last_seen': datetime.now().isoformat(),
                'status': 'active',
                'ports': [],
                'suspicious': False,
                'traffic': {
                    'packets': 0,
                    'bytes': 0,
                    'connections': defaultdict(int),
                    'last_minute_connections': 0
                }
            }
            
            if not skip_vendor_lookup:
                # Quick sync lookup for common vendors
                vendor, device_type = get_vendor_info_sync(mac)
                device_history[mac]['vendor'] = vendor
                device_history[mac]['device_type'] = device_type
                
                # If vendor is still unknown, queue a background lookup
                if vendor == "Unknown":
                    def vendor_update_callback(mac_addr, found_vendor, found_device_type):
                        """Callback to update device when vendor is found"""
                        if mac_addr in device_history:
                            device_history[mac_addr]['vendor'] = found_vendor
                            device_history[mac_addr]['device_type'] = found_device_type
                            print(f"Background vendor lookup completed: {mac_addr} -> {found_vendor} ({found_device_type})")
                    
                    request_vendor_lookup_async(mac, vendor_update_callback)
                
        else:
            device = device_history[mac]
            device['last_seen'] = datetime.now().isoformat()
            device['ip'] = ip
            
            if ip in packet_stats:
                device['traffic']['packets'] = packet_stats[ip]['packets']
                device['traffic']['bytes'] = packet_stats[ip]['bytes']
                
                new_ports = []
                for port in packet_stats[ip]['ports']:
                    service = get_service_name(port)
                    new_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                device['ports'] = new_ports
                
                alerts = check_device_alerts(mac, device)
                if alerts:
                    device['suspicious'] = True
                    asyncio.create_task(notify_clients_alerts(alerts))
                
    except Exception as e:
        print(f"Error updating device info: {str(e)}")

def get_service_name(port: int) -> str:
    """Get service name for common ports"""
    common_ports = {
        80: 'http',
        443: 'https',
        22: 'ssh',
        21: 'ftp',
        23: 'telnet',
        445: 'smb',
        3389: 'rdp',
        8080: 'http-proxy',
        53: 'dns',
        67: 'dhcp',
        68: 'dhcp',
        137: 'netbios',
        138: 'netbios',
        139: 'netbios',
        161: 'snmp',
        162: 'snmp'
    }
    return common_ports.get(port, 'unknown')

def start_packet_capture(interface: str):
    """Start packet capture on specified interface"""
    global is_sniffing
    is_sniffing = True
    
    def sniffer():
        try:
            print(f"Starting packet capture on interface {interface}")
            # On Windows, we need to use the interface GUID
            if platform.system() == "Windows":
                interfaces = get_windows_interfaces()
                interface_to_use = None
                
                # First try to find by name
                for guid, info in interfaces.items():
                    if info['name'] == interface:
                        interface_to_use = guid
                        break
                
                # If not found by name, try using the interface directly
                if not interface_to_use:
                    if interface in interfaces:
                        interface_to_use = interface
                    else:
                        # Try to find any valid interface
                        for guid, info in interfaces.items():
                            if info['ip'] and not info['ip'].startswith('127.'):
                                print(f"Using alternative interface: {info['name']} ({guid})")
                                interface_to_use = guid
                                break
                
                if not interface_to_use:
                    print("No suitable network interface found. Available interfaces:")
                    for guid, info in interfaces.items():
                        print(f"  - {info['name']} ({guid}): {info.get('ip', 'No IP')}")
                    return
                
                print(f"Using network interface: {interfaces[interface_to_use]['name']} ({interface_to_use})")
                sniff(iface=interface_to_use, prn=packet_callback, store=0, 
                      filter="ip or arp", stop_filter=lambda _: not is_sniffing)
            else:
                # For non-Windows systems
                sniff(iface=interface, prn=packet_callback, store=0, 
                      filter="ip or arp", stop_filter=lambda _: not is_sniffing)
                
        except Exception as e:
            print(f"Error in packet capture: {str(e)}")
            print("Available interfaces:")
            interfaces = get_windows_interfaces()
            for guid, info in interfaces.items():
                print(f"  - {info['name']} ({guid}): {info.get('ip', 'No IP')}")
    
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = Thread(target=sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()

async def get_network_info():
    """Get local network information"""
    try:
        interface_guid, gateway_ip, interface_name = get_default_gateway()
        
        if interface_guid and gateway_ip:
            # Get interface information
            if platform.system() == "Windows":
                interfaces = get_windows_interfaces()
                if interface_guid in interfaces:
                    iface_info = interfaces[interface_guid]
                    if iface_info['ip'] and iface_info['netmask']:
                        print(f"Using interface {interface_name} with IP {iface_info['ip']}")
                        return {
                            'interface': interface_name,
                            'ip': iface_info['ip'],
                            'netmask': iface_info['netmask'],
                            'gateway': gateway_ip
                        }
            
            # Fallback to netifaces
            addrs = netifaces.ifaddresses(interface_guid)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                print(f"Using interface {interface_name} with IP {ip}")
                return {
                    'interface': interface_name,
                    'ip': ip,
                    'netmask': netmask,
                    'gateway': gateway_ip
                }
        
        # Fallback: try all interfaces
        interfaces = get_windows_interfaces()
        for guid, info in interfaces.items():
            if info['ip'] and not info['ip'].startswith('127.'):
                print(f"Fallback: using interface {info['name']} with IP {info['ip']}")
                return {
                    'interface': info['name'],
                    'ip': info['ip'],
                    'netmask': info['netmask'],
                    'gateway': None
                }
    except Exception as e:
        print(f"Error getting network info: {str(e)}")
    return None

async def scan_network():
    """Enhanced network scanning with multiple techniques"""
    try:
        print("Starting network scan process...")
        network_info = await get_network_info()
        if not network_info:
            print("No suitable network interface found")
            return []
        
        print(f"Using interface: {network_info['interface']} ({network_info['ip']})")
        
        # Start packet capture if not already running
        start_packet_capture(network_info['interface'])
        
        # Perform multiple ARP scans with different techniques
        network = f"{network_info['ip']}/24"
        print(f"Scanning network: {network}")
        
        try:
            # Standard ARP scan
            print("Performing ARP scan...")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
            print(f"ARP scan found {len(ans)} devices")
            for sent, recv in ans:
                update_device_info(recv.psrc, recv.src, skip_vendor_lookup=True)
            
            if stop_scan_event.is_set():
                print("Scan stopped by user")
                return list(device_history.values())
            
            # Targeted scans for mobile device ports
            print("Performing targeted port scans...")
            for port in [62078, 5353, 137, 138]:  # Common mobile device ports
                if stop_scan_event.is_set():
                    break
                print(f"Scanning port {port}...")
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/
                    IP(dst=network)/
                    UDP(dport=port),
                    timeout=1,
                    verbose=False
                )
                for sent, recv in ans:
                    if IP in recv and Ether in recv:
                        update_device_info(recv[IP].src, recv[Ether].src, skip_vendor_lookup=True)
            
            if stop_scan_event.is_set():
                print("Scan stopped by user")
                return list(device_history.values())
            
            # mDNS discovery
            print("Performing mDNS discovery...")
            mdns_query = (
                IP(dst="224.0.0.251")/
                UDP(sport=5353, dport=5353)/
                DNS(
                    qr=0, opcode=0, aa=0, rd=0, ra=0,
                    qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR")
                )
            )
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/mdns_query, timeout=2, verbose=False)
            for sent, recv in ans:
                if IP in recv and Ether in recv:
                    update_device_info(recv[IP].src, recv[Ether].src, skip_vendor_lookup=True)
            
        except Exception as e:
            print(f"Error during network scanning: {str(e)}")
        
        if stop_scan_event.is_set():
            print("Scan stopped by user")
            return list(device_history.values())
        
        # Add a small delay to allow for packet processing
        print("Processing captured packets...")
        await asyncio.sleep(2)
        
        # After scan is complete, queue vendor lookups for all devices with unknown vendors
        if not stop_scan_event.is_set():
            print("Queuing background vendor lookups...")
            for mac in list(device_history.keys()):
                device = device_history[mac]
                if device['vendor'] == "Unknown":
                    def create_callback(device_mac):
                        def vendor_callback(mac_addr, found_vendor, found_device_type):
                            if mac_addr in device_history:
                                device_history[mac_addr]['vendor'] = found_vendor
                                device_history[mac_addr]['device_type'] = found_device_type
                                print(f"Scan vendor lookup complete: {mac_addr} -> {found_vendor}")
                        return vendor_callback
                    
                    request_vendor_lookup_async(mac, create_callback(mac))
        
        # Convert device history to list and return
        devices = list(device_history.values())
        print(f"Scan complete. Found {len(devices)} devices")
        return devices
        
    except Exception as e:
        print(f"Error in scan_network: {str(e)}")
        return []

async def notify_clients_alerts(alerts):
    """Notify all connected clients of new alerts"""
    for client in connected_clients:
        try:
            await client.send_json({
                'type': 'alerts',
                'data': alerts
            })
        except:
            continue

async def notify_device_update(device_mac: str):
    """Notify all connected clients of device updates"""
    if device_mac in device_history:
        device = device_history[device_mac]
        for client in connected_clients:
            try:
                await client.send_json({
                    'type': 'device_info',
                    'data': device
                })
            except:
                continue

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        print("New WebSocket connection attempt")
        await websocket.accept()
        connected_clients.append(websocket)
        print(f"Client connected. Total clients: {len(connected_clients)}")
        
        # Send initial connection confirmation
        await websocket.send_json({
            'type': 'connection_status',
            'status': 'connected'
        })
        
        # Send initial alerts
        await websocket.send_json({
            'type': 'alerts',
            'data': alert_history[-100:]  # Send last 100 alerts
        })
        
        # Initial scan without auto-update
        try:
            stop_scan_event.clear()  # Reset stop event
            print("Starting initial network scan...")
            devices = await scan_network()
            if websocket in connected_clients:  # Check if client is still connected
                await websocket.send_json({
                    'type': 'network_update',
                    'data': devices
                })
        except Exception as e:
            print(f"Error during initial scan: {str(e)}")
        
        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    continue
                
                message_type = data.get('type', '')
                print(f"Received message type: {message_type}")
                
                if message_type == 'ping':
                    if websocket in connected_clients:
                        await websocket.send_json({'type': 'pong'})
                
                elif message_type == 'manual_scan':
                    print("Manual scan requested - initiating scan...")
                    stop_scan_event.clear()  # Reset stop event
                    
                    # Notify scan start immediately
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'scan_start'
                        })
                    
                    # Start scan in background task
                    async def perform_scan():
                        try:
                            devices = await scan_network()
                            if websocket in connected_clients:
                                await websocket.send_json({
                                    'type': 'network_update',
                                    'data': devices
                                })
                                await websocket.send_json({
                                    'type': 'scan_complete'
                                })
                        except Exception as e:
                            print(f"Error during manual scan: {str(e)}")
                    
                    asyncio.create_task(perform_scan())
                
                elif message_type == 'stop_scan':
                    print("Stop scan requested")
                    stop_scan_event.set()  # Set stop event
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'scan_stopped'
                        })
                
                elif message_type == 'toggle_auto_scan':
                    global auto_scan
                    auto_scan = data.get('enabled', False)
                    print(f"Auto scan toggled: {auto_scan}")
                    if auto_scan:
                        stop_scan_event.clear()
                    else:
                        stop_scan_event.set()
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'auto_scan_status',
                            'enabled': auto_scan
                        })
                
                elif message_type == 'get_device_info':
                    device_mac = data.get('mac')
                    print(f"Device info requested for MAC: {device_mac}")
                    if device_mac in device_history and websocket in connected_clients:
                        device = device_history[device_mac]
                        
                        # If vendor is unknown, queue a background lookup
                        if device['vendor'] == "Unknown" or device['device_type'] == "Unknown":
                            print(f"Starting background vendor lookup for MAC: {device_mac}")
                            
                            def vendor_callback(mac_addr, found_vendor, found_device_type):
                                """Callback to send updated device info to client"""
                                if mac_addr in device_history:
                                    device_history[mac_addr]['vendor'] = found_vendor
                                    device_history[mac_addr]['device_type'] = found_device_type
                                    print(f"Background lookup complete - Vendor: {found_vendor}, Type: {found_device_type}")
                                    
                                    # Send updated info to all connected clients
                                    asyncio.create_task(notify_device_update(mac_addr))
                            
                            request_vendor_lookup_async(device_mac, vendor_callback)
                        
                        await websocket.send_json({
                            'type': 'device_info',
                            'data': device
                        })
                
                elif message_type == 'get_device_traffic':
                    device_mac = data.get('mac')
                    if device_mac in device_history and websocket in connected_clients:
                        device = device_history[device_mac]
                        await websocket.send_json({
                            'type': 'device_traffic',
                            'mac': device_mac,
                            'data': {
                                'traffic': device['traffic'],
                                'ports': device['ports'],
                                'connections': dict(device['traffic']['connections'])
                            }
                        })
                
            except asyncio.TimeoutError:
                try:
                    if websocket in connected_clients:
                        await websocket.send_json({'type': 'ping'})
                except:
                    break
                
                if auto_scan and not stop_scan_event.is_set() and websocket in connected_clients:
                    try:
                        print("Auto scan triggered")
                        devices = await scan_network()
                        await websocket.send_json({
                            'type': 'network_update',
                            'data': devices
                        })
                    except Exception as e:
                        print(f"Error during auto scan: {str(e)}")
                
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed by client")
                break
            
            except Exception as e:
                print(f"Error handling WebSocket message: {str(e)}")
                if "disconnect" in str(e).lower() or "connection" in str(e).lower():
                    break
                continue
                
    except Exception as e:
        print(f"WebSocket error during setup: {str(e)}")
        
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            print(f"Client disconnected. Remaining clients: {len(connected_clients)}")
        
        try:
            await websocket.close()
        except:
            pass

@app.get("/api/devices")
async def get_devices():
    """Get current network devices"""
    devices = await scan_network()
    return {"devices": devices}

@app.get("/api/interfaces")
async def get_interfaces():
    """Get available network interfaces"""
    if platform.system() == "Windows":
        return {"interfaces": get_windows_interfaces()}
    return {"interfaces": {}}

@app.get("/api/history")
async def get_device_history():
    """Get device history"""
    return {"history": device_history}

async def probe_device(ip: str, mac: str) -> dict:
    """Actively probe a device to gather more information"""
    device_info = {
        'os_type': 'Unknown',
        'open_ports': set(),
        'response_time': None,
        'is_up': False
    }
    
    try:
        # Send ICMP ping to check if device is up and get response time
        print(f"Sending ping to {ip}")
        ping_packet = IP(dst=ip)/ICMP()
        start_time = time.time()
        reply = await asyncio.get_event_loop().run_in_executor(
            thread_pool,
            lambda: sr1(ping_packet, timeout=1, verbose=0)
        )
        if reply:
            device_info['is_up'] = True
            device_info['response_time'] = (time.time() - start_time) * 1000
            device_info['ttl'] = reply.ttl
        
        # Quick port scan for most common ports
        print(f"Scanning common ports for {ip}")
        nm = nmap.PortScanner()
        common_ports = ','.join(map(str, [80, 443, 22, 23, 445, 139, 135, 8080, 8883, 1883, 62078, 5353]))
        await asyncio.get_event_loop().run_in_executor(
            thread_pool,
            lambda: nm.scan(ip, arguments=f'-n -Pn -sS -p{common_ports} --max-retries 1 --min-rate 1000')
        )
        
        if ip in nm.all_hosts():
            for port in nm[ip].all_tcp():
                if nm[ip]['tcp'][port]['state'] == 'open':
                    device_info['open_ports'].add(port)
        
        # Try service detection on open ports
        if device_info['open_ports']:
            ports_str = ','.join(map(str, list(device_info['open_ports'])[:5]))  # Limit to 5 ports
            await asyncio.get_event_loop().run_in_executor(
                thread_pool,
                lambda: nm.scan(ip, arguments=f'-sV -p{ports_str} --version-intensity 5')
            )
            
            if ip in nm.all_hosts():
                for port in nm[ip]['tcp']:
                    if 'product' in nm[ip]['tcp'][port]:
                        device_info['service_' + str(port)] = nm[ip]['tcp'][port]['product']
        
        return device_info
    except Exception as e:
        print(f"Error probing device {ip}: {e}")
        return device_info

def calculate_device_type_confidence(device_info: dict, ports: set) -> List[Tuple[str, float]]:
    """Calculate confidence scores for each device type"""
    scores = []
    
    for device_type, signature in PORT_SIGNATURES.items():
        score = 0.0
        required_ports = set(signature['required'])
        optional_ports = set(signature['optional'])
        weight = signature['weight']
        
        # Check required ports
        if required_ports and required_ports.intersection(ports):
            score += 0.6 * weight
        
        # Check optional ports
        optional_matches = len(optional_ports.intersection(ports))
        if optional_matches:
            score += (0.4 * weight * optional_matches / len(optional_ports))
        
        # Adjust score based on TTL if available
        if 'ttl' in device_info:
            ttl = device_info['ttl']
            if device_type == 'Network Device' and ttl > 240:
                score += 0.2
            elif device_type == 'Computer' and 100 <= ttl <= 128:
                score += 0.2
            elif device_type == 'Mobile Device' and 30 <= ttl <= 64:
                score += 0.2
        
        # Adjust score based on response time
        if device_info.get('response_time'):
            if device_type == 'Network Device' and device_info['response_time'] < 10:
                score += 0.1
            elif device_type in ['Computer', 'Gaming Console'] and device_info['response_time'] < 20:
                score += 0.1
        
        # Check service banners
        for port, service in device_info.items():
            if port.startswith('service_') and isinstance(service, str):
                service_lower = service.lower()
                if device_type == 'IoT Device' and any(x in service_lower for x in ['busybox', 'embedded']):
                    score += 0.2
                elif device_type == 'Network Device' and any(x in service_lower for x in ['cisco', 'router']):
                    score += 0.2
                elif device_type == 'Computer' and any(x in service_lower for x in ['windows', 'ubuntu', 'apache']):
                    score += 0.2
        
        scores.append((device_type, min(score, 1.0)))
    
    return sorted(scores, key=lambda x: x[1], reverse=True)

if __name__ == "__main__":
    # Start the vendor lookup service
    vendor_service.start()
    print("NetSentinel starting...")
    
    import uvicorn
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000)
    finally:
        # Stop the vendor service when shutting down
        vendor_service.stop()
        print("NetSentinel shutdown complete.") 