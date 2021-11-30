# Denial of Service in c

## What code is?
Source code for DoS(Denial of Service) Attack in Linux Environment.

## Feature of this code
- Ping of Death Attack <b>(Developing)</b>
<br>: Sending a Big size ICMP packet to target and make it busy. Big size ICMP packet will be fragmented, Delivered to a target system. Target will take fragment many packets. It makes overload to the target system. 
- SYN Flooding Attack <b>(Developed)</b>
<br>: This is an attack using the vulnerability of TCP 3-way handshaking. When the Client sends an SYN packet, the server will send the SYN and ACK Packet and wait for the Client's answer. At that time, the Attacker sends a lot of SYN packets. The server will overload due to a lot of waiting for the Client's answer.

## Usage
Will be updated...
This code can run in a Unix system. <br>
If you want to run this code in Windows System, You should use [WSL](https://docs.microsoft.com/en-us/windows/wsl/about) or [Cygwin](https://www.cygwin.com/) or Virtual Machine.
