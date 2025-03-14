#!/usr/bin/env python3

import os
import sys
import time
import curses
import threading
from queue import Queue
from common.common import *

class LogWindow:
    """Window for displaying log messages"""
    def __init__(self, height, width, y, x):
        self.window = curses.newwin(height, width, y, x)
        self.height = height
        self.width = width
        self.logs = []
        self.scroll_pos = 0
        self.window.box()
        self.window.addstr(0, 2, "Logs")
        self.window.refresh()
    
    def add_log(self, message):
        """Add a log message"""
        self.logs.append(message)
        if len(self.logs) > 1000:  # Keep last 1000 messages
            self.logs = self.logs[-1000:]
        self.scroll_pos = max(0, len(self.logs) - (self.height - 2))
        self.refresh()
    
    def scroll_up(self):
        """Scroll up in the log window"""
        if self.scroll_pos > 0:
            self.scroll_pos -= 1
            self.refresh()
    
    def scroll_down(self):
        """Scroll down in the log window"""
        if self.scroll_pos < len(self.logs) - (self.height - 2):
            self.scroll_pos += 1
            self.refresh()
    
    def refresh(self):
        """Refresh the log window"""
        self.window.clear()
        self.window.box()
        self.window.addstr(0, 2, "Logs")
        
        display_logs = self.logs[self.scroll_pos:self.scroll_pos + self.height - 2]
        for i, log in enumerate(display_logs):
            try:
                self.window.addnstr(i + 1, 1, log, self.width - 2)
            except curses.error:
                pass
        
        self.window.refresh()

class StatusWindow:
    """Window for displaying status information"""
    def __init__(self, height, width, y, x):
        self.window = curses.newwin(height, width, y, x)
        self.height = height
        self.width = width
        self.status = {}
        self.window.box()
        self.window.addstr(0, 2, "Status")
        self.window.refresh()
    
    def update_status(self, status):
        """Update status information"""
        self.status = status
        self.refresh()
    
    def refresh(self):
        """Refresh the status window"""
        self.window.clear()
        self.window.box()
        self.window.addstr(0, 2, "Status")
        
        y = 1
        if self.status:
            try:
                self.window.addstr(y, 1, f"Bridge Status: {self.status.get('bridge_status', 'Unknown')}")
                y += 1
                self.window.addstr(y, 1, f"Analysis Status: {self.status.get('analysis_status', 'Unknown')}")
                y += 1
                
                config = self.status.get('config', {})
                self.window.addstr(y, 1, "Configuration:")
                y += 1
                self.window.addstr(y, 2, f"Bridge: {config.get('bridge_name', 'Not set')}")
                y += 1
                self.window.addstr(y, 2, f"PHY Interface: {config.get('phy_interface', 'Not set')}")
                y += 1
                self.window.addstr(y, 2, f"Upstream Interface: {config.get('upstream_interface', 'Not set')}")
            except curses.error:
                pass
        
        self.window.refresh()

class MenuWindow:
    """Window for displaying menu options"""
    def __init__(self, height, width, y, x):
        self.window = curses.newwin(height, width, y, x)
        self.height = height
        self.width = width
        self.selected = 0
        self.options = [
            ("1", "Create Bridge"),
            ("2", "Destroy Bridge"),
            ("3", "Add Interaction"),
            ("4", "Force Reauth"),
            ("5", "Takeover Client"),
            ("6", "Start Analysis"),
            ("7", "Stop Analysis"),
            ("8", "View Config"),
            ("9", "Edit Config"),
            ("0", "Quit")
        ]
        self.window.box()
        self.window.addstr(0, 2, "Menu")
        self.refresh()
    
    def select_next(self):
        """Select next menu item"""
        self.selected = (self.selected + 1) % len(self.options)
        self.refresh()
    
    def select_prev(self):
        """Select previous menu item"""
        self.selected = (self.selected - 1) % len(self.options)
        self.refresh()
    
    def get_selected(self):
        """Get selected menu option"""
        return self.options[self.selected]
    
    def refresh(self):
        """Refresh the menu window"""
        self.window.clear()
        self.window.box()
        self.window.addstr(0, 2, "Menu")
        
        for i, (key, text) in enumerate(self.options):
            try:
                if i == self.selected:
                    self.window.attron(curses.A_REVERSE)
                self.window.addstr(i + 1, 1, f"{key}: {text}")
                if i == self.selected:
                    self.window.attroff(curses.A_REVERSE)
            except curses.error:
                pass
        
        self.window.refresh()

class OverviewWindow:
    """Window for displaying bridge overview"""
    def __init__(self, height, width, y, x):
        self.window = curses.newwin(height, width, y, x)
        self.height = height
        self.width = width
        self.status = {}
        self.window.box()
        self.window.addstr(0, 2, "Overview")
        self.window.refresh()
    
    def update_status(self, status):
        """Update status information"""
        self.status = status
        self.refresh()
    
    def refresh(self):
        """Refresh the overview window"""
        self.window.clear()
        self.window.box()
        self.window.addstr(0, 2, "Overview")
        
        if not self.status:
            return
        
        # Get status information
        config = self.status.get('config', {})
        bridge_status = self.status.get('bridge_status', 'NOT_CREATED')
        analysis_results = self.status.get('analysis_results', {})
        
        # Client box (left)
        client_y, client_x = 2, 2
        self.window.addstr(client_y, client_x, "┌─ Client ─────────┐")
        self.window.addstr(client_y + 1, client_x, "│ Status:         │")
        self.window.addstr(client_y + 2, client_x, "│ MAC:            │")
        self.window.addstr(client_y + 3, client_x, "│ IP:             │")
        self.window.addstr(client_y + 4, client_x, "│ DHCP: Y/N       │")
        self.window.addstr(client_y + 5, client_x, "└─────────────────┘")
        
        # Bridge box (middle)
        bridge_y, bridge_x = 2, 25
        self.window.addstr(bridge_y, bridge_x, "┌─ Bridge ─────────┐")
        self.window.addstr(bridge_y + 1, bridge_x, "│                 │")
        self.window.addstr(bridge_y + 2, bridge_x, "│    $ethX        │")
        self.window.addstr(bridge_y + 3, bridge_x, "│   Up/Down       │")
        self.window.addstr(bridge_y + 4, bridge_x, "│    $ethY        │")
        self.window.addstr(bridge_y + 5, bridge_x, "│   Up/Down       │")
        self.window.addstr(bridge_y + 6, bridge_x, "└─────────────────┘")
        
        # Network box (right)
        network_y, network_x = 2, 48
        self.window.addstr(network_y, network_x, "┌─ Network ────────┐")
        self.window.addstr(network_y + 1, network_x, "│ Status:         │")
        self.window.addstr(network_y + 2, network_x, "│ MAC:            │")
        self.window.addstr(network_y + 3, network_x, "│ IP CIDR:        │")
        self.window.addstr(network_y + 4, network_x, "│ GW:             │")
        self.window.addstr(network_y + 5, network_x, "└─────────────────┘")
        
        # Fill in values
        # Client status
        client_status = "CONNECTED" if analysis_results.get('client_mac') else "WAITING"
        self.window.addstr(client_y + 1, client_x + 9, f"{client_status:<10}")
        if analysis_results.get('client_mac'):
            self.window.addstr(client_y + 2, client_x + 6, f"{analysis_results['client_mac']:<12}")
        if analysis_results.get('client_ip'):
            self.window.addstr(client_y + 3, client_x + 5, f"{analysis_results['client_ip']:<14}")
        
        # Bridge status
        phy_interface = config.get('phy_interface', 'N/A')
        upstream_interface = config.get('upstream_interface', 'N/A')
        self.window.addstr(bridge_y + 2, bridge_x + 5, f"{phy_interface:<8}")
        self.window.addstr(bridge_y + 4, bridge_x + 5, f"{upstream_interface:<8}")
        
        # Network status
        network_status = "CONNECTED" if analysis_results.get('router_mac') else "WAITING"
        self.window.addstr(network_y + 1, network_x + 9, f"{network_status:<10}")
        if analysis_results.get('router_mac'):
            self.window.addstr(network_y + 2, network_x + 6, f"{analysis_results['router_mac']:<12}")
        if analysis_results.get('router_ip'):
            self.window.addstr(network_y + 3, network_x + 11, f"{analysis_results['router_ip']:<8}")
        
        self.window.refresh()

class SilentBridgeCLI:
    """Main CLI class"""
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.client = SilentBridgeClient()
        self.running = True
        self.log_queue = Queue()
        
        # Set up colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        
        # Get screen dimensions
        self.height, self.width = self.stdscr.getmaxyx()
        
        # Define minimum dimensions
        min_height = 35  # Minimum height needed
        min_width = 80   # Minimum width needed
        
        if self.height < min_height or self.width < min_width:
            curses.endwin()
            print(f"Terminal window too small. Minimum size required: {min_width}x{min_height}")
            print(f"Current size: {self.width}x{self.height}")
            sys.exit(1)
            
        # Create windows
        menu_height = 12
        overview_height = 10
        status_height = 8
        log_height = self.height - menu_height - status_height - overview_height
        
        # Ensure we have at least some space for logs
        if log_height < 5:
            log_height = 5
            status_height = max(3, self.height - menu_height - overview_height - log_height)
        
        self.menu_win = MenuWindow(menu_height, self.width, 0, 0)
        self.overview_win = OverviewWindow(overview_height, self.width, menu_height, 0)
        self.status_win = StatusWindow(status_height, self.width, menu_height + overview_height, 0)
        self.log_win = LogWindow(log_height, self.width, menu_height + overview_height + status_height, 0)
        
        # Hide cursor
        curses.curs_set(0)
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
    
    def update_loop(self):
        """Background thread for updating status and logs"""
        while self.running:
            try:
                # Update status
                response = self.client.get_status()
                if response and response.status == StatusCode.SUCCESS:
                    status_data = response.data
                    
                    # Get analysis results
                    analysis_response = self.client.get_analysis_results()
                    if analysis_response and analysis_response.status == StatusCode.SUCCESS:
                        status_data['analysis_results'] = analysis_response.data['results']
                    
                    self.status_win.update_status(status_data)
                    self.overview_win.update_status(status_data)
                
                # Update logs
                response = self.client.get_logs(lines=10)
                if response and response.status == StatusCode.SUCCESS:
                    for log in response.data.get('logs', []):
                        self.log_queue.put(log.strip())
                
                # Process log queue
                while not self.log_queue.empty():
                    log = self.log_queue.get_nowait()
                    self.log_win.add_log(log)
                
                time.sleep(1)
            except Exception as e:
                self.log_queue.put(f"Error in update loop: {e}")
                time.sleep(5)
    
    def create_bridge(self):
        """Handle create bridge menu option"""
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Create Bridge")
        self.stdscr.addstr(2, 0, "Bridge Name [br0]: ")
        self.stdscr.addstr(3, 0, "PHY Interface: ")
        self.stdscr.addstr(4, 0, "Upstream Interface: ")
        self.stdscr.refresh()
        
        curses.echo()
        curses.curs_set(1)
        
        bridge = self.stdscr.getstr(2, 16).decode() or "br0"
        phy = self.stdscr.getstr(3, 15).decode()
        upstream = self.stdscr.getstr(4, 20).decode()
        
        curses.noecho()
        curses.curs_set(0)
        
        if phy and upstream:
            response = self.client.create_bridge(bridge, phy, upstream)
            if response.status == StatusCode.SUCCESS:
                self.log_queue.put("Bridge created successfully")
            else:
                self.log_queue.put(f"Error creating bridge: {response.data.get('error', 'Unknown error')}")
        else:
            self.log_queue.put("Error: Missing required parameters")
    
    def destroy_bridge(self):
        """Handle destroy bridge menu option"""
        response = self.client.get_status()
        if response and response.status == StatusCode.SUCCESS:
            bridge = response.data.get('config', {}).get('bridge_name')
            if bridge:
                response = self.client.destroy_bridge(bridge)
                if response.status == StatusCode.SUCCESS:
                    self.log_queue.put("Bridge destroyed successfully")
                else:
                    self.log_queue.put(f"Error destroying bridge: {response.data.get('error', 'Unknown error')}")
            else:
                self.log_queue.put("Error: No bridge configured")
    
    def add_interaction(self):
        """Handle add interaction menu option"""
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Add Interaction")
        self.stdscr.addstr(2, 0, "Client MAC: ")
        self.stdscr.addstr(3, 0, "Client IP: ")
        self.stdscr.addstr(4, 0, "Gateway MAC: ")
        self.stdscr.refresh()
        
        curses.echo()
        curses.curs_set(1)
        
        client_mac = self.stdscr.getstr(2, 12).decode()
        client_ip = self.stdscr.getstr(3, 11).decode()
        gw_mac = self.stdscr.getstr(4, 13).decode()
        
        curses.noecho()
        curses.curs_set(0)
        
        if client_mac and client_ip and gw_mac:
            response = self.client.get_status()
            if response and response.status == StatusCode.SUCCESS:
                config = response.data.get('config', {})
                bridge = config.get('bridge_name')
                phy = config.get('phy_interface')
                upstream = config.get('upstream_interface')
                
                if bridge and phy and upstream:
                    response = self.client.add_interaction(bridge, phy, upstream, 
                                                         client_mac, client_ip, gw_mac)
                    if response.status == StatusCode.SUCCESS:
                        self.log_queue.put("Interaction added successfully")
                    else:
                        self.log_queue.put(f"Error adding interaction: {response.data.get('error', 'Unknown error')}")
                else:
                    self.log_queue.put("Error: Bridge not properly configured")
            else:
                self.log_queue.put("Error: Could not get bridge status")
        else:
            self.log_queue.put("Error: Missing required parameters")
    
    def force_reauth(self):
        """Handle force reauth menu option"""
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Force Reauthentication")
        self.stdscr.addstr(2, 0, "Client MAC: ")
        self.stdscr.refresh()
        
        curses.echo()
        curses.curs_set(1)
        
        client_mac = self.stdscr.getstr(2, 12).decode()
        
        curses.noecho()
        curses.curs_set(0)
        
        if client_mac:
            response = self.client.get_status()
            if response and response.status == StatusCode.SUCCESS:
                config = response.data.get('config', {})
                interface = config.get('phy_interface')
                
                if interface:
                    response = self.client.force_reauth(interface, client_mac)
                    if response.status == StatusCode.SUCCESS:
                        self.log_queue.put("Reauthentication forced successfully")
                    else:
                        self.log_queue.put(f"Error forcing reauthentication: {response.data.get('error', 'Unknown error')}")
                else:
                    self.log_queue.put("Error: No interface configured")
            else:
                self.log_queue.put("Error: Could not get configuration")
        else:
            self.log_queue.put("Error: Missing client MAC address")
    
    def takeover_client(self):
        """Handle takeover client menu option"""
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Takeover Client")
        self.stdscr.addstr(2, 0, "Client MAC: ")
        self.stdscr.addstr(3, 0, "Client IP: ")
        self.stdscr.addstr(4, 0, "Gateway IP: ")
        self.stdscr.addstr(5, 0, "Netmask [255.255.255.0]: ")
        self.stdscr.refresh()
        
        curses.echo()
        curses.curs_set(1)
        
        client_mac = self.stdscr.getstr(2, 12).decode()
        client_ip = self.stdscr.getstr(3, 11).decode()
        gateway_ip = self.stdscr.getstr(4, 12).decode()
        netmask = self.stdscr.getstr(5, 24).decode() or "255.255.255.0"
        
        curses.noecho()
        curses.curs_set(0)
        
        if client_mac and client_ip and gateway_ip:
            response = self.client.get_status()
            if response and response.status == StatusCode.SUCCESS:
                config = response.data.get('config', {})
                bridge = config.get('bridge_name')
                phy = config.get('phy_interface')
                veth = config.get('veth_name')
                
                if bridge and phy:
                    response = self.client.takeover_client(bridge, phy, client_mac, 
                                                         client_ip, gateway_ip, netmask, veth)
                    if response.status == StatusCode.SUCCESS:
                        self.log_queue.put("Client takeover successful")
                    else:
                        self.log_queue.put(f"Error in client takeover: {response.data.get('error', 'Unknown error')}")
                else:
                    self.log_queue.put("Error: Bridge not properly configured")
            else:
                self.log_queue.put("Error: Could not get configuration")
        else:
            self.log_queue.put("Error: Missing required parameters")
    
    def start_analysis(self):
        """Handle start analysis menu option"""
        response = self.client.get_status()
        if response and response.status == StatusCode.SUCCESS:
            config = response.data.get('config', {})
            interfaces = []
            
            if config.get('phy_interface'):
                interfaces.append(config['phy_interface'])
            if config.get('upstream_interface'):
                interfaces.append(config['upstream_interface'])
            
            if interfaces:
                response = self.client.start_analysis(interfaces)
                if response.status == StatusCode.SUCCESS:
                    self.log_queue.put("Analysis started successfully")
                else:
                    self.log_queue.put(f"Error starting analysis: {response.data.get('error', 'Unknown error')}")
            else:
                self.log_queue.put("Error: No interfaces configured")
        else:
            self.log_queue.put("Error: Could not get configuration")
    
    def stop_analysis(self):
        """Handle stop analysis menu option"""
        response = self.client.stop_analysis()
        if response.status == StatusCode.SUCCESS:
            self.log_queue.put("Analysis stopped successfully")
        else:
            self.log_queue.put(f"Error stopping analysis: {response.data.get('error', 'Unknown error')}")
    
    def view_config(self):
        """Handle view config menu option"""
        response = self.client.load_config()
        if response.status == StatusCode.SUCCESS:
            config = response.data.get('config', {})
            self.stdscr.clear()
            self.stdscr.addstr(0, 0, "Current Configuration:")
            y = 2
            for key, value in config.items():
                self.stdscr.addstr(y, 0, f"{key}: {value}")
                y += 1
            self.stdscr.addstr(y + 1, 0, "Press any key to continue...")
            self.stdscr.refresh()
            self.stdscr.getch()
        else:
            self.log_queue.put("Error loading configuration")
    
    def edit_config(self):
        """Handle edit config menu option"""
        response = self.client.load_config()
        if response.status == StatusCode.SUCCESS:
            config = response.data.get('config', {}).copy()
            
            self.stdscr.clear()
            self.stdscr.addstr(0, 0, "Edit Configuration")
            self.stdscr.addstr(1, 0, "(Press Enter to keep current value)")
            y = 3
            
            curses.echo()
            curses.curs_set(1)
            
            for key, value in config.items():
                self.stdscr.addstr(y, 0, f"{key} [{value}]: ")
                new_value = self.stdscr.getstr(y, len(key) + len(str(value)) + 4).decode()
                if new_value:
                    config[key] = new_value
                y += 1
            
            curses.noecho()
            curses.curs_set(0)
            
            response = self.client.save_config(config)
            if response.status == StatusCode.SUCCESS:
                self.log_queue.put("Configuration saved successfully")
            else:
                self.log_queue.put(f"Error saving configuration: {response.data.get('error', 'Unknown error')}")
        else:
            self.log_queue.put("Error loading configuration")
    
    def run(self):
        """Main run loop"""
        while self.running:
            try:
                # Get keyboard input
                key = self.stdscr.getch()
                
                if key == ord('q'):  # Quit
                    self.running = False
                elif key == curses.KEY_UP:  # Menu up
                    self.menu_win.select_prev()
                elif key == curses.KEY_DOWN:  # Menu down
                    self.menu_win.select_next()
                elif key == curses.KEY_PPAGE:  # Page up in logs
                    self.log_win.scroll_up()
                elif key == curses.KEY_NPAGE:  # Page down in logs
                    self.log_win.scroll_down()
                elif key == ord('\n'):  # Enter
                    option = self.menu_win.get_selected()
                    if option[0] == '1':
                        self.create_bridge()
                    elif option[0] == '2':
                        self.destroy_bridge()
                    elif option[0] == '3':
                        self.add_interaction()
                    elif option[0] == '4':
                        self.force_reauth()
                    elif option[0] == '5':
                        self.takeover_client()
                    elif option[0] == '6':
                        self.start_analysis()
                    elif option[0] == '7':
                        self.stop_analysis()
                    elif option[0] == '8':
                        self.view_config()
                    elif option[0] == '9':
                        self.edit_config()
                    elif option[0] == '0':
                        self.running = False
                
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                self.log_queue.put(f"Error in main loop: {e}")
                time.sleep(1)
        
        # Clean up
        self.client.disconnect()

def main():
    """Main entry point"""
    if os.geteuid() != 0:
        print("Error: This program must be run as root!")
        sys.exit(1)
    
    def run_cli(stdscr):
        cli = SilentBridgeCLI(stdscr)
        cli.run()
    
    curses.wrapper(run_cli)

if __name__ == '__main__':
    main() 