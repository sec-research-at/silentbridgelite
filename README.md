# SilentBridge

SilentBridge is a powerful 802.1x bypass tool that creates a transparent bridge between a client and network, allowing for network analysis and authentication bypass. It now features a daemon-based architecture with a curses-based control interface for improved reliability and user experience.

## Features

- Daemon-based architecture for improved stability and persistence
- Curses-based interactive control interface
- Automatic network analysis and configuration detection
- Support for both modern (NetworkManager, ip) and legacy (ifconfig, brctl) network stacks
- Transparent bridge creation with complete packet forwarding
- Client connection takeover with virtual interface
- Interactive mode for manual network manipulation
- Automatic cleanup and state restoration on failure
- Support for 802.1x reauthentication forcing
- Systemd service integration with security hardening
- Real-time network analysis and monitoring

## Requirements

- Python 3.7+
- Root privileges
- Linux system with systemd (for service installation)

### Dependencies

The following Python packages are required:
```
scapy>=2.6.1
netifaces>=0.11.0
nanpy>=0.9.6
python-daemon>=3.1.2
pyroute2>=0.8.1
psutil>=7.0.0
pyserial>=3.5
requests>=2.32.3
cryptography>=44.0.2
```

System packages required:
- bridge-utils
- macchanger
- ethtool
- net-tools
- iptables
- ebtables
- arptables

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/silentbridgelite.git
cd silentbridgelite
```

2. Install the package:
```bash
pip install -e .
```

3. Install as a system service (optional):
```bash
sudo python3 -m daemon.daemon --install-service
```

## Usage

### Service Management

SilentBridge can run as a system service with the following commands:

```bash
# Start the service
sudo systemctl start silentbridge

# Enable autostart on boot
sudo systemctl enable silentbridge

# Check service status
sudo systemctl status silentbridge

# View service logs
sudo journalctl -u silentbridge

# Stop the service
sudo systemctl stop silentbridge

# Disable autostart
sudo systemctl disable silentbridge

# Uninstall the service
sudo python3 -m daemon.daemon --uninstall-service
```

### Interactive CLI

The curses-based CLI provides an interactive interface to control the daemon:

```bash
sudo silentbridge-cli
```

The CLI interface provides the following features:
- Real-time log viewing
- Bridge status monitoring
- Network analysis control
- Client interaction management
- Configuration editing
- Service control

### Manual Daemon Control

You can also run the daemon directly:

```bash
# Run in foreground (for debugging)
sudo python3 -m daemon.daemon --nodaemon

# Run as daemon
sudo python3 -m daemon.daemon
```

## Architecture

SilentBridge consists of two main components:

1. **Daemon (silentbridged)**
   - Runs as a system service
   - Handles bridge creation and management
   - Performs network analysis
   - Manages client interactions
   - Provides IPC through Unix domain sockets

2. **CLI Interface (silentbridge-cli)**
   - Provides curses-based user interface
   - Connects to daemon via Unix socket
   - Displays real-time logs and status
   - Allows interactive control of all features

## Security Features

The systemd service is configured with security hardening:
- Protected system and home directories
- Private /tmp directory
- No new privileges
- Limited capabilities (NET_ADMIN, NET_RAW only)
- Automatic restart on failure
- Proper file permissions and ownership

## Configuration

Configuration files are stored in the following locations:
- `/etc/silentbridge/` - System configuration
- `/var/log/silentbridge/` - Log files
- `/var/run/silentbridge/` - Runtime files

## Troubleshooting

1. Service fails to start:
   ```bash
   # Check service status
   sudo systemctl status silentbridge
   
   # View detailed logs
   sudo journalctl -u silentbridge -n 50
   ```

2. CLI cannot connect to daemon:
   - Verify the daemon is running
   - Check socket permissions
   - Ensure you have root privileges

3. Bridge creation fails:
   - Check system logs
   - Verify interface names and availability
   - Ensure required kernel modules are loaded

4. Analysis not working:
   - Verify interface permissions
   - Check packet capture capabilities
   - Monitor real-time logs

## Security Considerations

- This tool is for educational and testing purposes only
- Always obtain proper authorization before testing
- The tool creates a transparent bridge that can intercept all traffic
- Run with minimal required privileges when possible

## License

This project is for educational purposes only. Use responsibly and only on networks you own or have explicit permission to test.