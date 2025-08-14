# TCP-IP-Hijack-via-RST-signal-
(Wrriten in C)TCP/IP hijack using PCAP and LIBNET library for capturing and injection TCP/IP packages - This code simply spoof victim ip address , and send TCP/IP packet to DST using RST flag , so Victim machine loose access to the internet , Fundamental of how to fully hijack a session.
**Disclaimer:**  
This code is provided for educational and research purposes only. Do **not** use it on networks or devices you do not own or have explicit permission to test.  
The author is not responsible for misuse.

## How to Build

gcc RST_Hijack.c -o rst_hijack -lpcap -lnet

## Files
- `RST_Hijack.c`: Main logic
- `Fatal.c`: Helper functions



