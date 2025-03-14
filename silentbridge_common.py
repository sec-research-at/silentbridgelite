#!/usr/bin/env python3

import os
import json
import socket
import struct
import time
import logging
from enum import Enum, auto
from pathlib import Path

# Constants
DEFAULT_CONFIG_PATH = os.path.expanduser('~/.silentbridge/config.json')
DEFAULT_SOCKET_PATH = os.path.expanduser('~/.silentbridge/silentbridge.sock')
DEFAULT_LOG_PATH = os.path.expanduser('~/.silentbridge/silentbridge.log')
DEFAULT_PID_FILE = '/var/run/silentbridged.pid'

# Ensure the config directory exists
os.makedirs(os.path.dirname(DEFAULT_CONFIG_PATH), exist_ok=True)

# Command types for daemon-client communication
class CommandType(Enum):
    # Status commands
    GET_STATUS = auto()
    GET_INTERFACES = auto()
    GET_BRIDGE_STATUS = auto()
    GET_ANALYSIS_RESULTS = auto()
    GET_LOGS = auto()
    
    # Configuration commands
    SAVE_CONFIG = auto()
    LOAD_CONFIG = auto()
    
    # Bridge operations
    CREATE_BRIDGE = auto()
    DESTROY_BRIDGE = auto()
    ADD_INTERACTION = auto()
    FORCE_REAUTH = auto()
    TAKEOVER_CLIENT = auto()
    
    # Analysis operations
    START_ANALYSIS = auto()
    STOP_ANALYSIS = auto()
    
    # Daemon control
    SHUTDOWN = auto()
    RESTART = auto()

# Default configuration
DEFAULT_CONFIG = {
    'bridge_name': 'br0',
    'veth_name': 'veth0',
    'phy_interface': None,
    'upstream_interface': None,
    'client_mac': None,
    'client_ip': None,
    'router_mac': None,
    'router_ip': None,
    'log_level': 'INFO',
    'analysis_timeout': 30,
    'use_legacy_iptables': False,
    'autostart_enabled': False
}

# Status codes
class StatusCode(Enum):
    SUCCESS = 0
    ERROR = 1
    NOT_IMPLEMENTED = 2
    INVALID_COMMAND = 3
    PERMISSION_DENIED = 4
    BRIDGE_EXISTS = 5
    BRIDGE_DOES_NOT_EXIST = 6
    INTERFACE_NOT_FOUND = 7
    ANALYSIS_RUNNING = 8
    ANALYSIS_NOT_RUNNING = 9

# Bridge status
class BridgeStatus(Enum):
    NOT_CREATED = 0
    CREATED = 1
    INTERACTIVE = 2
    TAKEOVER = 3

# Analysis status
class AnalysisStatus(Enum):
    NOT_RUNNING = 0
    RUNNING = 1
    COMPLETED = 2
    FAILED = 3

# Message format for daemon-client communication
class Message:
    def __init__(self, command_type, data=None, status=StatusCode.SUCCESS):
        self.command_type = command_type
        self.data = data if data is not None else {}
        self.status = status
    
    def to_json(self):
        return json.dumps({
            'command': self.command_type.name,
            'data': self.data,
            'status': self.status.name
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(
            CommandType[data['command']],
            data.get('data', {}),
            StatusCode[data['status']]
        )

# Socket communication helpers
def send_message(sock, message):
    """Send a message over a socket with length prefix"""
    msg_json = message.to_json()
    msg_bytes = msg_json.encode('utf-8')
    length = len(msg_bytes)
    sock.sendall(struct.pack('!I', length) + msg_bytes)

def receive_message(sock):
    """Receive a message from a socket with length prefix"""
    # Receive the length prefix (4 bytes)
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    
    length = struct.unpack('!I', length_bytes)[0]
    
    # Receive the message data
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            return None
        data += chunk
    
    # Parse the message
    return Message.from_json(data.decode('utf-8'))

# Configuration management
def load_config(config_path=DEFAULT_CONFIG_PATH):
    """Load configuration from file"""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Merge with default config to ensure all keys exist
                merged_config = DEFAULT_CONFIG.copy()
                merged_config.update(config)
                return merged_config
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
    
    return DEFAULT_CONFIG.copy()

def save_config(config, config_path=DEFAULT_CONFIG_PATH):
    """Save configuration to file"""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error saving configuration: {e}")
        return False

# Logging setup
def setup_logging(log_path=DEFAULT_LOG_PATH, log_level='INFO'):
    """Set up logging configuration"""
    # Ensure the directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    # Map string log level to logging constants
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    level = level_map.get(log_level, logging.INFO)
    
    # Configure logging
    logging.basicConfig(
        filename=log_path,
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

# Daemon management
def is_daemon_running():
    """Check if the daemon is running"""
    if os.path.exists(DEFAULT_PID_FILE):
        try:
            with open(DEFAULT_PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process exists
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, PermissionError):
            # Process doesn't exist or PID file is invalid
            return False
    return False

def get_daemon_pid():
    """Get the daemon PID if running"""
    if os.path.exists(DEFAULT_PID_FILE):
        try:
            with open(DEFAULT_PID_FILE, 'r') as f:
                return int(f.read().strip())
        except (ValueError, IOError):
            return None
    return None

# Network interface helpers
def get_available_interfaces():
    """Get a list of available network interfaces"""
    interfaces = []
    try:
        for iface in os.listdir('/sys/class/net'):
            # Skip loopback and virtual interfaces
            if iface != 'lo' and not iface.startswith(('veth', 'br', 'docker', 'virbr')):
                interfaces.append(iface)
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
    
    return interfaces

def check_interface_exists(interface):
    """Check if an interface exists"""
    return os.path.exists(f"/sys/class/net/{interface}")

def check_interface_in_bridge(bridge, interface):
    """Check if an interface is already in a bridge"""
    if not os.path.exists(f"/sys/devices/virtual/net/{bridge}/brif"):
        return False
    
    try:
        bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{bridge}/brif")
        return interface in bridge_interfaces
    except:
        return False

# Client connection to daemon
class SilentBridgeClient:
    def __init__(self, socket_path=DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path
        self.sock = None
    
    def connect(self):
        """Connect to the daemon socket"""
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            return True
        except Exception as e:
            logging.error(f"Error connecting to daemon: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the daemon socket"""
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def send_command(self, command_type, data=None):
        """Send a command to the daemon and get the response"""
        if not self.sock:
            if not self.connect():
                return Message(command_type, status=StatusCode.ERROR, 
                              data={'error': 'Failed to connect to daemon'})
        
        try:
            message = Message(command_type, data)
            send_message(self.sock, message)
            response = receive_message(self.sock)
            return response
        except Exception as e:
            logging.error(f"Error sending command to daemon: {e}")
            self.disconnect()
            return Message(command_type, status=StatusCode.ERROR, 
                          data={'error': str(e)})
    
    def get_status(self):
        """Get the daemon status"""
        return self.send_command(CommandType.GET_STATUS)
    
    def get_interfaces(self):
        """Get available network interfaces"""
        return self.send_command(CommandType.GET_INTERFACES)
    
    def get_bridge_status(self):
        """Get the bridge status"""
        return self.send_command(CommandType.GET_BRIDGE_STATUS)
    
    def get_analysis_results(self):
        """Get the latest analysis results"""
        return self.send_command(CommandType.GET_ANALYSIS_RESULTS)
    
    def get_logs(self, lines=100):
        """Get the latest log entries"""
        return self.send_command(CommandType.GET_LOGS, {'lines': lines})
    
    def save_config(self, config):
        """Save configuration"""
        return self.send_command(CommandType.SAVE_CONFIG, {'config': config})
    
    def load_config(self):
        """Load configuration"""
        return self.send_command(CommandType.LOAD_CONFIG)
    
    def create_bridge(self, bridge_name, phy_interface, upstream_interface, use_legacy=False):
        """Create a transparent bridge"""
        data = {
            'bridge_name': bridge_name,
            'phy_interface': phy_interface,
            'upstream_interface': upstream_interface,
            'use_legacy': use_legacy
        }
        return self.send_command(CommandType.CREATE_BRIDGE, data)
    
    def destroy_bridge(self, bridge_name):
        """Destroy a bridge"""
        return self.send_command(CommandType.DESTROY_BRIDGE, {'bridge_name': bridge_name})
    
    def add_interaction(self, bridge_name, phy_interface, upstream_interface, 
                       client_mac, client_ip, gw_mac, use_legacy=False):
        """Add interaction to bridge"""
        data = {
            'bridge_name': bridge_name,
            'phy_interface': phy_interface,
            'upstream_interface': upstream_interface,
            'client_mac': client_mac,
            'client_ip': client_ip,
            'gw_mac': gw_mac,
            'use_legacy': use_legacy
        }
        return self.send_command(CommandType.ADD_INTERACTION, data)
    
    def force_reauth(self, interface, client_mac):
        """Force 802.1x reauthentication"""
        data = {
            'interface': interface,
            'client_mac': client_mac
        }
        return self.send_command(CommandType.FORCE_REAUTH, data)
    
    def takeover_client(self, bridge_name, phy_interface, client_mac, client_ip, 
                       gateway_ip, netmask='255.255.255.0', veth_name='veth0'):
        """Take over client connection"""
        data = {
            'bridge_name': bridge_name,
            'phy_interface': phy_interface,
            'client_mac': client_mac,
            'client_ip': client_ip,
            'gateway_ip': gateway_ip,
            'netmask': netmask,
            'veth_name': veth_name
        }
        return self.send_command(CommandType.TAKEOVER_CLIENT, data)
    
    def start_analysis(self, interfaces, timeout=30):
        """Start network analysis"""
        data = {
            'interfaces': interfaces,
            'timeout': timeout
        }
        return self.send_command(CommandType.START_ANALYSIS, data)
    
    def stop_analysis(self):
        """Stop network analysis"""
        return self.send_command(CommandType.STOP_ANALYSIS)
    
    def shutdown_daemon(self):
        """Shutdown the daemon"""
        return self.send_command(CommandType.SHUTDOWN)
    
    def restart_daemon(self):
        """Restart the daemon"""
        return self.send_command(CommandType.RESTART) 