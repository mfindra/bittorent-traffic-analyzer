import sys
import csv
import subprocess
import tempfile

def extract_bootstrap_nodes(csv_file):
    bootstrap_nodes = set()

    with open(csv_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=';')
        for row in csv_reader:                                 
            if row and 'get_peers' in str(row) and str(row[7]).endswith("y,q") and str(row[7]).startswith("a,bs,id"):
                bootstrap_nodes.add((row[2], row[3]))

    return sorted(list(bootstrap_nodes), key=lambda x: x[1])

def extract_peers(csv_file):
    peers_nodes = set()
    connections = dict()

    with open(csv_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=';')
        for row in csv_reader:
            if row and 'nodes' in str(row) and str(row[7]).endswith("y,r"):
                ip_field = row[5]
                port_field = row[6]
                ids_field = row[10]

                nodes_flags = row[8]
                peers_flags = row[9]
                n_flags = nodes_flags.split(',')
                if len(peers_flags) != 0:
                    peers_flags = peers_flags.split(',')

                ips = (ip_field.split(','))
                ports = (port_field.split(','))
                ids = (ids_field.split(','))

                for i in range(len(n_flags)):
                    if n_flags[i] == '1':
                        key = (ips[i], int(ports[i]), ids[i])
                        peers_nodes.add(key)
                        connections[key] = 0

                for i in range(len(peers_flags)):
                    if peers_flags[i] == '1':
                        key = (ips[i], int(ports[i]), ids[i])
                        peers_nodes.add(key)
                        connections[key] = 0

        # Second iteration to count connections
        csvfile.seek(0)  # Move the file pointer back to the beginning
        for row in csv_reader:
            if row and str(row[7]).endswith("y,r"):
                src_ip = row[1]
                src_port = int(row[4])

                for key in peers_nodes:
                    if key[0] == src_ip and key[1] == src_port:
                        connections[key] += 1
                        break
    
    sorted_peers_nodes = sorted(list(peers_nodes), key=lambda x: x[1])
    return [(node[0], node[1], node[2], connections[node]) for node in sorted_peers_nodes]





def process_pcap(pcap_file, mode):
    with tempfile.NamedTemporaryFile(mode='w+t', delete=False) as temp_csv:
        tshark_command = [
            'tshark', '-r', pcap_file, '-T', 'fields', '-E', 'separator=;', '-d', 'udp.port==47222,bt-dht',
            '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'udp.dstport', '-e', 'udp.srcport', '-e', 'bt-dht.ip', '-e', 'bt-dht.port',
            '-e', 'bt-dht.bencoded.string', '-e', 'bt-dht.node', '-e', 'bt-dht.peer', '-e', 'bt-dht.id',
            '-e', 'bittorrent.piece.index', '-e', 'bittorrent.piece.begin', '-e', 'bittorrent.piece.length',
            '-e', 'bittorrent.peer_id', '-e', 'bittorrent.info_hash', '-e', 'bittorrent.msg.type',
            '-e', 'tcp.srcport', '-e', 'tcp.dstport', 'bt-dht or bittorrent or bt-utp'
        ]

        try:
            subprocess.run(tshark_command, stdout=temp_csv, check=True)
            temp_csv.seek(0)
            if mode == "init":
                return extract_bootstrap_nodes(temp_csv.name)
            elif mode == "peers":
                return extract_peers(temp_csv.name)
        except subprocess.CalledProcessError as e:
            print(f"Error: TShark command failed with exit code {e.returncode}")
            return []

def main(argv):
    input_path = None
    input_type = None
    init_mode = False
    peers_mode = False


    for i in range(len(argv)):
        if argv[i] == '-csv' or argv[i] == '-pcap':
            input_type = argv[i]
            input_path = argv[i + 1]
        elif argv[i] == '-init':
            init_mode = True
        elif argv[i] == '-peers':
            peers_mode = True

    if not input_path or not input_type:
        print("Error: No input path provided. Use -csv <path> or -pcap <path> to specify the path.")
        return

    if init_mode:
        if input_type == '-csv':
            bootstrap_nodes = extract_bootstrap_nodes(input_path)
        elif input_type == '-pcap':
            bootstrap_nodes = process_pcap(input_path, "init")

        print("Bootstrap nodes (sorted by port):")
        for node in bootstrap_nodes:
            print(f"{node[0]}:{node[1]}")

    if peers_mode:
        if input_type == '-csv':
            bootstrap_nodes = extract_peers(input_path)
        elif input_type == '-pcap':
            bootstrap_nodes = process_pcap(input_path, "peers")

        print("Bootstrap nodes (sorted by port):")
        for node in bootstrap_nodes:
            print(f"{node[0]}:{node[1]} {node[2]} {node[3]}")


if __name__ == "__main__":
    main(sys.argv[1:])