# Bittorrent pcap/csv file parser and analyzer

## prerequisites: 
1. tshark 4.0.7
2. python 3.6.7<
3. requirements.txt (pip install -r requirements.txt)

## Usage
The program accepts both pcap/pcapng and csv files. 
Program is based on captured traffic from qBitTorrentClient.

CSV file needs to follow strict form, which can be generated using following command
``` bash
tshark -r <filename> -T fields -E separator=";" -d udp.port==47222,bt-dht -e frame.time_relative -e ip.src -e ip.dst -e udp.dstport -e udp.srcport -e bt-dht.ip -e bt-dht.port -e bt-dht.bencoded.string -e bt-dht.node -e bt-dht.peer -e bt-dht.id -e bittorrent.piece.index  -e bittorrent.piece.length -e bittorrent.peer_id -e bittorrent.info_hash -e bittorrent.msg.type -e dns.a -e tcp.dstport "bt-dht or bittorrent or bt-utp or dns or udp or tcp"
```

PCAP/PCAPNG can just be supplied as argument and will be parsed internally. 

### Syntax

``` bash
bt-monitor -pcap <file.pcap>|-csv <file.csv> -init | -peers | -download | -rtable
```

- `<file.pcap>`: Input PCAP file containing BitTorrent network traffic
- `<file.csv>`: Input CSV file containing parsed BitTorrent network traffic

### Functionalities

- `-init`: Returns a list of detected bootstrap nodes (IP, port)
- `-peers`: Returns a list of detected neighbors (IP, port, node ID, number of connections)
- `-download`: Returns file information including info_hash, size, chunks, and contributing nodes (IP+port)
- `-rtable`: Returns the routing table of the client (node IDs, IP, ports)

### Usage Examples

- Analyzing PCAP file:
``` bash
    ./bt-monitor -pcap test2.pcapng -init
    ./bt-monitor -csv test2.csv -rtable
```