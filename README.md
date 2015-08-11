# netray

A simple but colorful live network traffic visualizer for layer 2, 3 and 4. (MAC, IPv4, ARP, TCP, UDP) 

Needs root or use the wunderful setuid alternative posix file capabilities like this:

`# setcap cap_net_raw+ep /usr/bin/netray`
