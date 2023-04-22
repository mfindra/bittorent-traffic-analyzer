import sys
import csv
import subprocess
import tempfile
from enum import Enum

class peerMessage(Enum):
    CHOKE = "0"
    UNCHOKE = "1"
    INTERESTED = "2"
    NOT_INTERESTED = "3"
    HAVE = "4"
    BITFIELD = "5"
    REQUEST = "6"
    PIECE = "7"
    CANCEL = "8"
    HAVE_ALL = "20"

class csvFields(Enum):
    FRAME_TIME_RELATIVE = 0
    IP_SRC = 1
    IP_DST = 2
    UDP_DSTPORT = 3
    UDP_SRCPORT = 4
    BT_DHT_IP = 5
    BT_DHT_PORT = 6
    BT_DHT_BENCODED_STRING = 7
    BT_DHT_NODE = 8
    BT_DHT_PEER = 9
    BT_DHT_ID = 10
    BT_PIECE_INDEX = 11
    BT_PIECE_LENGTH = 12
    BT_PEER_ID = 13
    BT_INFO_HASH = 14
    BT_MSG_TYPE = 15
    DNS_A = 16


def extract_bootstrap_nodes(csv_file):
    bootstrap_nodes = set()

    try:
         # open file and prepare lines for parsing
        with open(csv_file, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=';')
            # try parsing using "bs" key in bencoded data part
            for row in csv_reader:                                 
                if row and 'get_peers' in str(row) and str(row[csvFields.BT_DHT_BENCODED_STRING.value]).endswith("y,q") and str(row[csvFields.BT_DHT_BENCODED_STRING.value]).startswith("a,bs,id"):
                    bootstrap_nodes.add((row[csvFields.IP_DST.value], row[csvFields.UDP_DSTPORT.value]))
                    
        # alternative method for getting bootstrap nodes, using DNS
        if len(bootstrap_nodes) == 0:
            print("(DNS variant) ", end="")
            all_nodes_set = set()
            dns_ips = set()

            with open(csv_file, newline='') as csvfile:
                csv_reader = csv.reader(csvfile, delimiter=';')
                for row in csv_reader:

                    # parse only DNS packets
                    if row and row[csvFields.DNS_A.value]:
                        dnss_split = row[csvFields.DNS_A.value].split(',')
                        for ip in dnss_split:
                            dns_ips.add(ip)

                    # save addresses, to which requests were made to
                    if row and str(row[csvFields.BT_DHT_BENCODED_STRING.value]).endswith("y,r"):                     
                        all_nodes_set.add((row[1],  int(row[csvFields.UDP_SRCPORT.value])))
                    
            bootstrap_nodes = {node for node in all_nodes_set if node[0] in dns_ips}

        print("Bootstrap nodes:")
        for node in sorted(list(bootstrap_nodes), key=lambda x: x[1]):
            print(f"{node[0]}:{node[1]}")
    except (IOError, FileNotFoundError):
        print(f"Error: Could not read file {csv_file}")

    return 

def extract_peers(csv_file):
    peers_nodes = set()
    connections = dict()
    try:
        with open(csv_file, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=';')
            for row in csv_reader:
                if row and 'nodes' in str(row) and str(row[csvFields.BT_DHT_BENCODED_STRING.value]).endswith("y,r"):
                    ip_field = row[csvFields.BT_DHT_IP.value]
                    port_field = row[csvFields.BT_DHT_PORT.value]
                    ids_field = row[csvFields.BT_DHT_ID.value]

                    nodes_flags = row[csvFields.BT_DHT_NODE.value]
                    peers_flags = row[csvFields.BT_DHT_PEER.value]
                    nodes_flags = nodes_flags.split(',')                
                    if len(peers_flags) != 0:
                        peers_flags = peers_flags.split(',')

                    ips = (ip_field.split(','))
                    ports = (port_field.split(','))
                    ids = (ids_field.split(','))

                    if (len(ips) != (len(nodes_flags)) + len(peers_flags)):
                        ips.pop(0)
                        ports.pop(0)

                    for i in range(len(nodes_flags)):
                        if nodes_flags[i] == '1':
                            key = (ips[i], int(ports[i]), ids[i])
                            peers_nodes.add(key)
                            connections[key] = 0

                    for i in range(len(peers_flags)):
                        if peers_flags[i] == '1':
                            key = (ips[len(nodes_flags) +i], int(ports[len(nodes_flags) +i]), "none")
                            peers_nodes.add(key)
                            connections[key] = 0
            
            # Second iteration to count connections
            csvfile.seek(0)  
            for row in csv_reader:
                if row and str(row[csvFields.BT_DHT_BENCODED_STRING.value]).endswith("y,r"):
                    src_ip = row[1]
                    src_port = int(row[csvFields.UDP_SRCPORT.value])

                    for key in peers_nodes:
                        if key[0] == src_ip and key[1] == src_port:
                            connections[key] += 1
                            break
        
        sorted_peers_nodes = sorted(list(peers_nodes), key=lambda x: x[1])

        print("Neighbor nodes:")
        for node in [(node[0], node[1], node[2], connections[node]) for node in sorted_peers_nodes]:
            print(f"{node[0]}:{node[1]} {node[2]} {node[3]}")
            
    except (IOError, FileNotFoundError):
        print(f"Error: Could not read file {csv_file}")
    return

def extract_download(csv_file):
    try:
    # open file and prepare lines for parsing
        with open(csv_file, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=';')

            info_hash = ""
            interested_peers = set()
            handshake_peers = set()
            
            # extract all addresses, client send Interested(2) message to
            for row in csv_reader:
                if peerMessage.INTERESTED.value in str(row[csvFields.BT_MSG_TYPE.value]) and not peerMessage.HAVE_ALL.value in str(row[csvFields.BT_MSG_TYPE.value]):
                    interested_peers.add(row[csvFields.IP_DST.value])
            
            # extract addresses from Handshakes with with users from Interested 
            csvfile.seek(0)
            for row in csv_reader:
                for peer in interested_peers:
                    if row[csvFields.BT_PEER_ID.value] and row[csvFields.BT_INFO_HASH.value] and not row[csvFields.BT_MSG_TYPE.value] and (peer == row[csvFields.IP_DST.value]):
                        handshake_peers.add((peer, row[csvFields.BT_INFO_HASH.value]))

            contributors = 0
            chunks = 0
            file_parts = []
            
            # extract chunks exchanged with Handshaked users by flag Request(6) in BitTorrent packets
            for peer in handshake_peers:
                csvfile.seek(0)
                ids = []
                for row in csv_reader:

                    sixes = 0
                    if row[csvFields.IP_DST.value] == peer[0] and row[csvFields.BT_PIECE_LENGTH.value]:
                        len_pieces = row[csvFields.BT_PIECE_LENGTH.value].split(',')
                        ids_list = row[csvFields.BT_PIECE_INDEX.value].split(',')
                        flags = row[csvFields.BT_MSG_TYPE.value].split(',')


                        for i in range(len(ids_list)):
                            if flags[i] == "6":
                                ids.append((peer[0], ids_list[i], int(len_pieces[sixes], 16)))
                                sixes+=1
                                chunks+=1

                # merge parts of same chunks and count the bite size
                merged_data = {}
                for tup in ids:
                    key = tup[1]
                    length = tup[2]
                    if key in merged_data:
                        merged_data[key] += length
                    else:
                        merged_data[key] = length

                file_parts.append(merged_data)

            # extract info_hash and number of contributors based on amount of chunk exchanged.
            max_chunks = -1
            for i, part in enumerate(file_parts):
                if len(part) > 0:
                    contributors+=1
                if max_chunks < len(part):
                    max_chunks = len(part)
                    info_hash = list(handshake_peers)[i][1]
            
            # if parts are downloaded from multiple sources, keep only greater one, to prevent incorrect counts 
            max_values = {}
            for lst in file_parts:
                for key, value in lst.items():
                    if key not in max_values:
                        max_values[key] = value
                    else:
                        max_values[key] = max(max_values[key], value)


            print(f"Length of file is: {sum(max_values.values())}, number of chunks: {chunks}, info_hash is: {info_hash}, contributors: {contributors}")

    except (IOError, FileNotFoundError):
        print(f"Error: Could not read file {csv_file}")

    return



def process_pcap(pcap_file, mode):
    with tempfile.NamedTemporaryFile(mode='w+t', delete=False) as temp_csv:
        tshark_command = [
            'tshark', '-r', pcap_file, '-T', 'fields', '-E', 'separator=;', '-d', 'udp.port==47222,bt-dht',
            '-e', 'frame.time_relative',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.dstport',
            '-e', 'udp.srcport',
            '-e', 'bt-dht.ip',
            '-e', 'bt-dht.port',           
            '-e', 'bt-dht.bencoded.string',
            '-e', 'bt-dht.node',
            '-e', 'bt-dht.peer',
            '-e', 'bt-dht.id',           
            '-e', 'bittorrent.piece.index',
            '-e', 'bittorrent.piece.length',           
            '-e', 'bittorrent.peer_id',
            '-e', 'bittorrent.info_hash',
            '-e', 'bittorrent.msg.type',           
            '-e', 'dns.a', 'bt-dht or bittorrent or bt-utp or dns'
        ]


        try:
            subprocess.run(tshark_command, stdout=temp_csv, check=True)
            temp_csv.seek(0)
            if mode == "init":
                return extract_bootstrap_nodes(temp_csv.name)
            elif mode == "peers":
                return extract_peers(temp_csv.name)
            elif mode == "download":
                return extract_download(temp_csv.name)
        except subprocess.CalledProcessError as e:
            print(f"Error: TShark command failed with exit code {e.returncode}")
            return []

def main(argv):
    input_path = None
    input_type = None
    init_mode = False
    peers_mode = False
    download_mode = False 

    for i in range(len(argv)):
        if argv[i] == '-csv' or argv[i] == '-pcap':
            input_type = argv[i]
            input_path = argv[i + 1]
        elif argv[i] == '-init':
            init_mode = True
        elif argv[i] == '-peers':
            peers_mode = True
        elif argv[i] == '-download':
            download_mode = True
        elif argv[i] != input_path:
            print("Error: Unrecognized argument " + argv[i] + ".")
            return

    if not input_path or not input_type:
        print("Error: No input path provided. Use -csv <path> or -pcap <path> to specify the path.")
        return

    if init_mode:
        if input_type == '-csv':
            extract_bootstrap_nodes(input_path)
        elif input_type == '-pcap':
            process_pcap(input_path, "init")

    if peers_mode:
        if input_type == '-csv':
            extract_peers(input_path)
        elif input_type == '-pcap':
            process_pcap(input_path, "peers")

    if download_mode:
        if input_type == '-csv':
            extract_download(input_path)
        elif input_type == '-pcap':
            process_pcap(input_path, "download")

if __name__ == "__main__":
    main(sys.argv[1:])