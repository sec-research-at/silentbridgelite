#!/usr/bin/env python3

import os
import sys
import time
import signal
import socket
import threading
import logging
import argparse
import daemon
import daemon.pidfile
from queue import Queue
from scapy.all import Ether, EAPOL, DHCP, sniff, BOOTP, sendp
from silentbridge_common import *

class AnalysisThread(threading.Thread):
    """Thread for continuous network analysis"""
    def __init__(self, daemon):
        super().__init__()
        self.daemon = daemon
        self.stop_event = threading.Event()
        self.packet_queue = Queue()
        self.status = AnalysisStatus.NOT_RUNNING
        self.results = {
            'client_mac': None,
            'client_ip': None,
            'router_mac': None,
            'router_ip': None,
            'phy_interface': None,
            'upstream_interface': None
        }
    
    def run(self):
        """Main analysis loop"""
        while not self.stop_event.is_set():
            try:
                if self.status == AnalysisStatus.RUNNING:
                    self.analyze_network()
                else:
                    time.sleep(1)
            except Exception as e:
                logging.error(f"Error in analysis thread: {e}")
                self.status = AnalysisStatus.FAILED
                time.sleep(5)  # Wait before retrying
    
    def start_analysis(self, interfaces=None):
        """Start network analysis"""
        if self.status == AnalysisStatus.RUNNING:
            return False
        
        self.interfaces = interfaces or self.daemon.get_monitored_interfaces()
        if not self.interfaces:
            logging.error("No interfaces specified for analysis")
            return False
        
        # Clear previous results
        self.results = {key: None for key in self.results}
        self.status = AnalysisStatus.RUNNING
        return True
    
    def stop_analysis(self):
        """Stop network analysis"""
        if self.status != AnalysisStatus.RUNNING:
            return False
        
        self.status = AnalysisStatus.NOT_RUNNING
        return True
    
    def analyze_network(self):
        """Analyze network traffic for authentication and DHCP packets"""
        try:
            # Start packet capture on all interfaces
            for iface in self.interfaces:
                if not check_interface_exists(iface):
                    logging.error(f"Interface {iface} does not exist")
                    continue
                
                def capture_packets(iface):
                    try:
                        sniff(iface=iface,
                             prn=self.packet_callback,
                             store=0,
                             stop_filter=lambda _: self.status != AnalysisStatus.RUNNING)
                    except Exception as e:
                        logging.error(f"Error capturing packets on {iface}: {e}")
                
                thread = threading.Thread(target=capture_packets, args=(iface,))
                thread.daemon = True
                thread.start()
            
            # Process packets from the queue
            while self.status == AnalysisStatus.RUNNING:
                try:
                    packet = self.packet_queue.get(timeout=1)
                    self.process_packet(packet)
                except Exception as e:
                    if not isinstance(e, Queue.Empty):
                        logging.error(f"Error processing packet: {e}")
        
        except Exception as e:
            logging.error(f"Error in network analysis: {e}")
            self.status = AnalysisStatus.FAILED
    
    def packet_callback(self, packet):
        """Callback for packet capture"""
        if self.status == AnalysisStatus.RUNNING:
            self.packet_queue.put(packet)
    
    def process_packet(self, packet):
        """Process a captured packet"""
        try:
            # Extract interface and MAC addresses
            interface = packet.sniffed_on
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Check for EAPOL packets
            if EAPOL in packet:
                if packet[EAPOL].type == 1:  # EAPOL-Start
                    self.results['client_mac'] = src_mac
                    self.results['phy_interface'] = interface
                    logging.info(f"Detected EAPOL-Start from {src_mac} on {interface}")
                
                # Check for EAP packets
                if packet.haslayer('EAP'):
                    if packet['EAP'].code == 1:  # Request
                        if packet['EAP'].type == 1:  # Identity
                            self.results['router_mac'] = src_mac
                            self.results['upstream_interface'] = interface
                            logging.info(f"Detected EAP Identity Request from {src_mac} on {interface}")
            
            # Check for DHCP packets
            if DHCP in packet:
                message_type = None
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        message_type = opt[1]
                        break
                
                if message_type == 3:  # DHCP Request
                    self.results['client_mac'] = src_mac
                    self.results['phy_interface'] = interface
                    logging.info(f"Detected DHCP Request from {src_mac} on {interface}")
                
                elif message_type == 5:  # DHCP ACK
                    self.results['router_mac'] = src_mac
                    self.results['router_ip'] = packet[BOOTP].siaddr
                    self.results['client_ip'] = packet[BOOTP].yiaddr
                    self.results['upstream_interface'] = interface
                    logging.info(f"Detected DHCP ACK: Client IP {self.results['client_ip']}, Router IP {self.results['router_ip']}")
            
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

class SilentBridgeDaemon:
    """Main daemon class for SilentBridge"""
    def __init__(self):
        self.config = load_config()
        self.bridge_status = BridgeStatus.NOT_CREATED
        self.stop_event = threading.Event()
        self.clients = []
        
        # Initialize analysis thread
        self.analysis_thread = AnalysisThread(self)
        
        # Command handlers
        self.command_handlers = {
            CommandType.GET_STATUS: self.handle_get_status,
            CommandType.GET_INTERFACES: self.handle_get_interfaces,
            CommandType.GET_BRIDGE_STATUS: self.handle_get_bridge_status,
            CommandType.GET_ANALYSIS_RESULTS: self.handle_get_analysis_results,
            CommandType.GET_LOGS: self.handle_get_logs,
            CommandType.SAVE_CONFIG: self.handle_save_config,
            CommandType.LOAD_CONFIG: self.handle_load_config,
            CommandType.CREATE_BRIDGE: self.handle_create_bridge,
            CommandType.DESTROY_BRIDGE: self.handle_destroy_bridge,
            CommandType.ADD_INTERACTION: self.handle_add_interaction,
            CommandType.FORCE_REAUTH: self.handle_force_reauth,
            CommandType.TAKEOVER_CLIENT: self.handle_takeover_client,
            CommandType.START_ANALYSIS: self.handle_start_analysis,
            CommandType.STOP_ANALYSIS: self.handle_stop_analysis,
            CommandType.SHUTDOWN: self.handle_shutdown,
            CommandType.RESTART: self.handle_restart
        }
    
    def run(self):
        """Main daemon loop"""
        try:
            # Set up logging
            setup_logging(log_level=self.config['log_level'])
            
            # Start analysis thread
            self.analysis_thread.start()
            
            # Create socket server
            if os.path.exists(DEFAULT_SOCKET_PATH):
                os.unlink(DEFAULT_SOCKET_PATH)
            
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(DEFAULT_SOCKET_PATH)
            os.chmod(DEFAULT_SOCKET_PATH, 0o666)  # Allow other users to connect
            server.listen(5)
            
            logging.info("SilentBridge daemon started")
            
            while not self.stop_event.is_set():
                try:
                    # Accept client connections with timeout
                    server.settimeout(1.0)
                    try:
                        client, _ = server.accept()
                        self.handle_client(client)
                    except socket.timeout:
                        continue
                    
                except Exception as e:
                    logging.error(f"Error in main loop: {e}")
                    time.sleep(1)
            
            logging.info("Shutting down daemon...")
            server.close()
            
            # Cleanup
            self.cleanup()
            
        except Exception as e:
            logging.error(f"Fatal error in daemon: {e}")
            self.cleanup()
            sys.exit(1)
    
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            while True:
                message = receive_message(client_socket)
                if not message:
                    break
                
                handler = self.command_handlers.get(message.command_type)
                if handler:
                    response = handler(message.data)
                else:
                    response = Message(message.command_type, 
                                     status=StatusCode.INVALID_COMMAND,
                                     data={'error': 'Invalid command'})
                
                send_message(client_socket, response)
        
        except Exception as e:
            logging.error(f"Error handling client: {e}")
        
        finally:
            client_socket.close()
    
    def cleanup(self):
        """Clean up resources"""
        # Stop analysis thread
        self.analysis_thread.stop_event.set()
        self.analysis_thread.join()
        
        # Destroy bridge if it exists
        if self.bridge_status != BridgeStatus.NOT_CREATED:
            try:
                self.handle_destroy_bridge({'bridge_name': self.config['bridge_name']})
            except:
                pass
        
        # Remove socket file
        try:
            os.unlink(DEFAULT_SOCKET_PATH)
        except:
            pass
    
    def get_monitored_interfaces(self):
        """Get interfaces that should be monitored"""
        interfaces = []
        
        # Add bridge interface if it exists
        if self.bridge_status != BridgeStatus.NOT_CREATED:
            interfaces.append(self.config['bridge_name'])
        
        # Add configured interfaces
        if self.config['phy_interface']:
            interfaces.append(self.config['phy_interface'])
        if self.config['upstream_interface']:
            interfaces.append(self.config['upstream_interface'])
        
        return list(set(interfaces))  # Remove duplicates
    
    # Command handlers
    def handle_get_status(self, data):
        """Handle GET_STATUS command"""
        status = {
            'bridge_status': self.bridge_status.name,
            'analysis_status': self.analysis_thread.status.name,
            'config': self.config
        }
        return Message(CommandType.GET_STATUS, data=status)
    
    def handle_get_interfaces(self, data):
        """Handle GET_INTERFACES command"""
        interfaces = get_available_interfaces()
        return Message(CommandType.GET_INTERFACES, data={'interfaces': interfaces})
    
    def handle_get_bridge_status(self, data):
        """Handle GET_BRIDGE_STATUS command"""
        status = {
            'status': self.bridge_status.name,
            'bridge_name': self.config['bridge_name'],
            'phy_interface': self.config['phy_interface'],
            'upstream_interface': self.config['upstream_interface']
        }
        return Message(CommandType.GET_BRIDGE_STATUS, data=status)
    
    def handle_get_analysis_results(self, data):
        """Handle GET_ANALYSIS_RESULTS command"""
        return Message(CommandType.GET_ANALYSIS_RESULTS, 
                      data={'results': self.analysis_thread.results})
    
    def handle_get_logs(self, data):
        """Handle GET_LOGS command"""
        lines = data.get('lines', 100)
        try:
            with open(DEFAULT_LOG_PATH, 'r') as f:
                log_lines = f.readlines()[-lines:]
            return Message(CommandType.GET_LOGS, data={'logs': log_lines})
        except Exception as e:
            return Message(CommandType.GET_LOGS, 
                         status=StatusCode.ERROR,
                         data={'error': str(e)})
    
    def handle_save_config(self, data):
        """Handle SAVE_CONFIG command"""
        config = data.get('config')
        if not config:
            return Message(CommandType.SAVE_CONFIG,
                         status=StatusCode.ERROR,
                         data={'error': 'No configuration provided'})
        
        self.config.update(config)
        if save_config(self.config):
            return Message(CommandType.SAVE_CONFIG)
        else:
            return Message(CommandType.SAVE_CONFIG,
                         status=StatusCode.ERROR,
                         data={'error': 'Failed to save configuration'})
    
    def handle_load_config(self, data):
        """Handle LOAD_CONFIG command"""
        self.config = load_config()
        return Message(CommandType.LOAD_CONFIG, data={'config': self.config})
    
    def handle_create_bridge(self, data):
        """Handle CREATE_BRIDGE command"""
        if self.bridge_status != BridgeStatus.NOT_CREATED:
            return Message(CommandType.CREATE_BRIDGE,
                         status=StatusCode.BRIDGE_EXISTS,
                         data={'error': 'Bridge already exists'})
        
        # Implementation of create_bridge logic here
        # This will be similar to the original create_transparent_bridge method
        # but adapted for the daemon architecture
        
        return Message(CommandType.CREATE_BRIDGE)
    
    def handle_destroy_bridge(self, data):
        """Handle DESTROY_BRIDGE command"""
        if self.bridge_status == BridgeStatus.NOT_CREATED:
            return Message(CommandType.DESTROY_BRIDGE,
                         status=StatusCode.BRIDGE_DOES_NOT_EXIST,
                         data={'error': 'Bridge does not exist'})
        
        # Implementation of destroy_bridge logic here
        
        return Message(CommandType.DESTROY_BRIDGE)
    
    def handle_add_interaction(self, data):
        """Handle ADD_INTERACTION command"""
        if self.bridge_status != BridgeStatus.CREATED:
            return Message(CommandType.ADD_INTERACTION,
                         status=StatusCode.ERROR,
                         data={'error': 'Bridge not in correct state'})
        
        # Implementation of add_interaction logic here
        
        return Message(CommandType.ADD_INTERACTION)
    
    def handle_force_reauth(self, data):
        """Handle FORCE_REAUTH command"""
        # Implementation of force_reauth logic here
        return Message(CommandType.FORCE_REAUTH)
    
    def handle_takeover_client(self, data):
        """Handle TAKEOVER_CLIENT command"""
        if self.bridge_status != BridgeStatus.CREATED:
            return Message(CommandType.TAKEOVER_CLIENT,
                         status=StatusCode.ERROR,
                         data={'error': 'Bridge not in correct state'})
        
        # Implementation of takeover_client logic here
        
        return Message(CommandType.TAKEOVER_CLIENT)
    
    def handle_start_analysis(self, data):
        """Handle START_ANALYSIS command"""
        interfaces = data.get('interfaces')
        if self.analysis_thread.start_analysis(interfaces):
            return Message(CommandType.START_ANALYSIS)
        else:
            return Message(CommandType.START_ANALYSIS,
                         status=StatusCode.ERROR,
                         data={'error': 'Failed to start analysis'})
    
    def handle_stop_analysis(self, data):
        """Handle STOP_ANALYSIS command"""
        if self.analysis_thread.stop_analysis():
            return Message(CommandType.STOP_ANALYSIS)
        else:
            return Message(CommandType.STOP_ANALYSIS,
                         status=StatusCode.ERROR,
                         data={'error': 'Analysis not running'})
    
    def handle_shutdown(self, data):
        """Handle SHUTDOWN command"""
        self.stop_event.set()
        return Message(CommandType.SHUTDOWN)
    
    def handle_restart(self, data):
        """Handle RESTART command"""
        # Implementation of restart logic here
        return Message(CommandType.RESTART)

def main():
    parser = argparse.ArgumentParser(description='SilentBridge Daemon')
    parser.add_argument('--nodaemon', action='store_true',
                       help='Run in foreground (do not daemonize)')
    args = parser.parse_args()
    
    # Check if already running
    if is_daemon_running():
        print("Error: SilentBridge daemon is already running")
        sys.exit(1)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This program must be run as root!")
        sys.exit(1)
    
    daemon_context = daemon.DaemonContext(
        pidfile=daemon.pidfile.PIDLockFile(DEFAULT_PID_FILE),
        signal_map={
            signal.SIGTERM: lambda signo, frame: None,
            signal.SIGHUP: lambda signo, frame: None,
        }
    )
    
    if args.nodaemon:
        # Run in foreground
        bridge_daemon = SilentBridgeDaemon()
        bridge_daemon.run()
    else:
        # Daemonize
        with daemon_context:
            bridge_daemon = SilentBridgeDaemon()
            bridge_daemon.run()

if __name__ == '__main__':
    main() 