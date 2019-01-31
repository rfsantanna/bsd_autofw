# BSD Auto Firewall

A small script to add rules based on traffic using ipfw.

### Prerequisites

```
pkg install python36
pkg install tcpdump
```

## **Quick Start**

```
git clone https://github.com/rfsantanna/bsd_autofw.git
curl -O https://github.com/rfsantanna/bsd_autofw/raw/master/bsd_autofw.py
``` 

#### Usage:

```
usage: firewall.py [-h] -i INTERFACE [-t TIMEOUT] [-rt RULE_TIMEOUT]
                   [--filter FILTERS] [-n CONNECTIONS] [--syn] [--debug]
                   [--apply]
                   address

Include firewall rules by tcpdump output

positional arguments:
  address

optional arguments:
  -h, --help        show this help message and exit
  -i INTERFACE      Select a interface to sniff
  -t TIMEOUT        timeout of tcpdump command
  -rt RULE_TIMEOUT  rollback rule after seconds
  --filter FILTERS  filters in tcpdump format(separated by comma)
  -n CONNECTIONS    Maximum connections before apply rule
  --syn             Deny only SYN packets (keep estabilished connections)
  --debug           show match packets
  --apply           Aplly Rules based on number of connections passed on -n
                    parameter
```
### Tips
 - the sniffer only catch new connections requests (with SYN FLAG)
 - use `--debug` to show  all new connection packets
 - the default timeout of tcpdump is 10 seconds, change with `-t number`
 - Firewall don't drop estabilished connections with `--syn` 
 - add filters (ex.: `--filter "port 22"`)
 - The rules automatically rollback with `-rt`
 - Finally, apply rules with `--apply`


### Examples

 - Sniff ena0 interface for 20 seconds. 
 - If number of new connections is greather than 3
 - don't drop estabilished connections
 - rollback firewall rule after 60 seconds
 - show packets
 - confirm apply
 
`python3.6 bsd_autofw.py -i ena0 -t 20 -n 3 --syn -rt 60 --debug --apply HOST_IP_ADDR`

![alt text](https://github.com/rfsantanna/bsd_autofw/raw/master/ex.png)
