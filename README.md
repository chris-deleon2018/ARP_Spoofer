# ARP Spoofer
Simple ARP Spoofer to Perform a Man-in-the-Middle using Scapy. The python script gets the MAC address of the victim and victim's gateway MAC address. Then the script uses the MAC address of the computer the script is running from to spoof the victim's gateway address to perform the man-in-the-middle attack. 

*Note: The script uses the IPv4 forward queue which is limited to Linux.*

## How to Run
```
python arp_spoofer.py -v <victim_ip> -g <gateway_ip>
```

## Help Menu
```
arp_spoofer.py [-h] [-v VICTIMIP] [-g GATEWAYIP]

optional arguments:
  -h, --help            show this help message and exit
  -v VICTIMIP, --victim VICTIMIP
                        Victim IP Address
  -g GATEWAYIP, --gateway GATEWAYIP
                        Default Gateway IP Address
```


*Disclaimer: The script was created to provide a simple proof of concept. This script should be soley used for educational purposes.*
