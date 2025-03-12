# SilentBridge Python 3.x

A modern Python 3.x implementation of the core functionality from the SilentBridge toolkit for 802.1x port security bypass.

## Overview

This script provides the core functionality needed to:
- Create a transparent bridge for 802.1x bypass
- Reset/destroy a bridge
- Add interaction to a bridge (for traffic manipulation)
- Force 802.1x reauthentication via EAPOL-Start packets
- Take over a client's connection by creating a virtual interface

## Requirements

- Python 3.6+
- Root/sudo privileges
- Linux system with the following tools installed:
  - `brctl` (bridge-utils)
  - `iptables`
  - `ebtables`
  - `arptables`
  - `macchanger`
  - `ethtool`
  - `ip` (iproute2)

## Installation

1. Install the required Python packages:
   ```
   pip3 install -r requirements.txt
   ```

2. Make the script executable:
   ```
   chmod +x silentbridge.py
   ```

## Usage

The script provides several commands for different operations:

### Create a Transparent Bridge

```bash
sudo ./silentbridge.py create --bridge br0 --phy eth1 --upstream eth2 --sidechannel eth0 --egress-port 22
```

This creates a transparent bridge named `br0` with `eth1` (physical interface connected to the network) and `eth2` (upstream interface) as slaves. The `eth0` interface is used as a side channel for management access.

### Destroy a Bridge

```bash
sudo ./silentbridge.py destroy --bridge br0
```

This destroys the bridge named `br0` and frees all its slave interfaces.

### Add Interaction to a Bridge

```bash
sudo ./silentbridge.py interact --bridge br0 --phy eth1 --upstream eth2 --sidechannel eth0 --egress-port 22 --client-mac 00:11:22:33:44:55 --client-ip 192.168.1.100 --gw-mac 00:aa:bb:cc:dd:ee
```

This adds interaction capabilities to the bridge, allowing you to impersonate a client with the specified MAC and IP addresses.

### Force 802.1x Reauthentication

```bash
sudo ./silentbridge.py reauth --interface eth1 --client-mac 00:11:22:33:44:55
```

This sends an EAPOL-Start packet from the specified interface, impersonating the client with the given MAC address, to force 802.1x reauthentication.

### Take Over Client Connection

```bash
sudo ./silentbridge.py takeover --bridge br0 --phy eth1 --client-mac 00:11:22:33:44:55 --client-ip 192.168.1.100 --gateway-ip 192.168.1.1 --veth-name veth0
```

This command removes the physical interface from the bridge and creates a virtual Ethernet device with the client's MAC and IP address. The client is effectively disconnected from the network, and the system takes over the client's connection. This allows direct access to the network using the client's identity without the need for NAT or other traffic manipulation techniques.

## Security Considerations

This tool is intended for legitimate security testing and research purposes only. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal and unethical.

## Acknowledgments

This project is a modern Python 3.x reimplementation of the original SilentBridge toolkit created by Gabriel Ryan ([@s0lst1c3](https://twitter.com/s0lst1c3)) at SpecterOps. The original project was first presented at DEF CON 26 and provided the first documented means of bypassing 802.1x-2010 via its authentication process, as well as improvements to existing techniques for bypassing 802.1x-2004.

The original SilentBridge project either builds upon, is inspired by, or directly incorporates over ten years of prior research and development from the following researchers:

- Steve Riley - Hub-based 802.1x-2004 bypass
- Alva Duckwall - Bridge-based 802.1x-2004 bypass
- Abb - Tap-based 802.1x-2004 bypass
- Valerian Legrand - Injection-based 802.1x-2004 bypass
- Josh Wright and Brad Antoniewicz - Attacks Against Weak EAP Methods
- Dom White and Ian de Villier - More Attacks Against Weak EAP Methods
- Moxie Marlinspike and David Hulton - Attacks Against MS-CHAPv2

For more information about the original research, you can check out the accompanying whitepaper at [Bypassing Port Security In 2018 - Defeating MACsec and 802.1x-2010](https://www.researchgate.net/publication/327402715_Bypassing_Port_Security_In_2018_-_Defeating_MACsec_and_8021x-2010).

## License

This project is licensed under the GNU General Public License v3.0, the same license as the original SilentBridge toolkit. The full text of the license can be found in the `LICENSE` file.

## Disclaimer

This tool is provided for educational and research purposes only. The author is not responsible for any misuse or damage caused by this tool. 