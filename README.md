# wireshark-jnx-itch
Wireshark dissector for JNX ITCH protocol

# Installation
The build instructions are documented in the [`build.sh`](build.sh) script. It
also addresses a common issue in RHEL and derivatives.

To install, follow the instructions at the end of the build script.

# Usage
To check if the plugin is correctly discovered and loaded:
```
tshark -G plugins
```

To see the list of possible fields:

```
tshark -G fields | grep jnx_
```

To decode correctly, tell wireshark to use the soupbintcp decoder on the ports which have the correct session. E.g.:

```
tshark -d tcp.port==12100-12199,soupbintcp
```

## Example:

Show all unsequenced packets

```
tshark -d tcp.port==12100-12199,soupbintcp -r dump.pcap -T fields -e soupbintcp.packet_type -e jnx_ouch.message_type -e jnx_ouch.order_token soupbintcp.packet_type=="'U'"
```
