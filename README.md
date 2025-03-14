# SilentBridge

SilentBridge is a powerful 802.1x bypass tool that creates a transparent bridge between a client and network, allowing for network analysis and authentication bypass.

## Features

- Automatic network analysis and configuration detection
- Support for both modern (NetworkManager, ip) and legacy (ifconfig, brctl) network stacks
- Transparent bridge creation with complete packet forwarding
- Client connection takeover with virtual interface
- Interactive mode for manual network manipulation
- Automatic cleanup and state restoration on failure
- Support for 802.1x reauthentication forcing
- Automatic tool installation for multiple package managers
- Autostart configuration for system boot (systemd and SysVinit)

## Requirements

- Python 3.6+
- Root privileges

You can automatically install all required tools using:
```bash
sudo python3 silentbridge.py install-tools
```

This will check for and install:
- System packages (using your system's package manager):
  - python3-pip
  - bridge-utils
  - macchanger
  - ethtool
  - net-tools
  - iptables
  - ebtables
  - arptables
- Python packages:
  - scapy
  - netifaces

Supported package managers:
- apt (Debian/Ubuntu)
- yum (RHEL/CentOS)
- dnf (Fedora)
- pacman (Arch Linux)
- zypper (openSUSE)
- apk (Alpine Linux)

## Usage

### Automatic Takeover (Recommended)

The easiest way to use SilentBridge is with the autotakeover command:

```bash
python3 silentbridge.py autotakeover --interfaces eth0 eth1
```

This will:
1. Analyze the network to determine which interface is connected to the client and which to the network
2. Create a transparent bridge
3. Capture client authentication
4. Take over the client's connection

### Manual Commands

#### Analyze Network

Analyze interfaces to determine configuration:

```bash
python3 silentbridge.py analyze --interfaces eth0 eth1
```

#### Create Bridge

Create a transparent bridge (with optional stored config):

```bash
python3 silentbridge.py create --bridge br0 --phy eth0 --upstream eth1
# Or using stored configuration:
python3 silentbridge.py create --bridge br0 --use-stored-config
```

#### Add Interaction

Add interaction capabilities to the bridge:

```bash
python3 silentbridge.py interact --bridge br0 --phy eth0 --upstream eth1 \
                               --client-mac 00:11:22:33:44:55 --client-ip 192.168.1.100 \
                               --gw-mac 00:11:22:33:44:66
```

#### Force Reauthentication

Force 802.1x reauthentication:

```bash
python3 silentbridge.py reauth --interface eth0 --client-mac 00:11:22:33:44:55
```

#### Take Over Client

Take over a client's connection:

```bash
python3 silentbridge.py takeover --bridge br0 --phy eth0 --client-mac 00:11:22:33:44:55 \
                                --client-ip 192.168.1.100 --gateway-ip 192.168.1.1
```

#### Destroy Bridge

Clean up and destroy the bridge:

```bash
python3 silentbridge.py destroy --bridge br0
```

#### Configure Autostart

Enable SilentBridge to start automatically at boot:

```bash
# Enable autostart with 'create' command (default)
sudo python3 silentbridge.py autostart --enable --phy eth0 --upstream eth1

# Enable autostart with 'autotakeover' command
sudo python3 silentbridge.py autostart --enable --command autotakeover --interfaces eth0 eth1

# Disable autostart
sudo python3 silentbridge.py autostart --disable
```

## Configuration

SilentBridge automatically saves detected configurations to `~/.silentbridge`. This configuration can be reused with the `--use-stored-config` option.

## Network Stack Support

SilentBridge automatically detects and uses the appropriate network stack:

- Modern systems:
  - NetworkManager
  - ip command (iproute2)
  - bridge command
- Legacy systems:
  - ifconfig
  - brctl
  - route

## Troubleshooting

1. If interfaces are not detected:
   - Ensure you have the correct permissions (run as root)
   - Check if interfaces are managed by NetworkManager
   - Verify interface names are correct

2. If bridge creation fails:
   - Ensure bridge-utils is installed
   - Check if interfaces are already in use
   - Verify kernel modules (br_netfilter) are available

3. If packet capture fails:
   - Ensure Scapy is installed correctly
   - Check if interfaces are up
   - Verify promiscuous mode is supported

4. If autostart doesn't work:
   - Check system logs with `journalctl -u silentbridge` (systemd) or `/var/log/syslog` (SysVinit)
   - Verify the service is enabled with `systemctl status silentbridge` (systemd) or `service silentbridge status` (SysVinit)
   - Ensure the script path in the service file is correct

## Security Considerations

- This tool is for educational and testing purposes only
- Always obtain proper authorization before testing
- The tool creates a transparent bridge that can intercept all traffic

## License

This project is for educational purposes only. Use responsibly and only on networks you own or have explicit permission to test.