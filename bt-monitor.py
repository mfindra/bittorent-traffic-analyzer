import sys
import csv
import subprocess
import tempfile

def extract_bootstrap_nodes(csv_file):
    bootstrap_nodes = set()

    with open(csv_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=';')
        for row in csv_reader:
            if row and 'nodes' in str(row) and 'ip' in str(row):
                ip_field = row[3]
                port_field = row[4]

                ips = ip_field.split(',')
                ports = port_field.split(',')

                if len(ips) == len(ports):
                    for i in range(len(ips)):
                        bootstrap_nodes.add((ips[i], int(ports[i])))

    return sorted(list(bootstrap_nodes), key=lambda x: x[1])

def process_pcap(pcap_file):
    with tempfile.NamedTemporaryFile(mode='w+t', delete=False) as temp_csv:
        tshark_command = [
            'tshark', '-r', pcap_file, '-T', 'fields', '-E', 'separator=;', '-d', 'udp.port==47222,bt-dht',
            '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'bt-dht.ip', '-e', 'bt-dht.port',
            '-e', 'bt-dht.bencoded.string', 'bt-dht'
        ]

        try:
            subprocess.run(tshark_command, stdout=temp_csv, check=True)
            temp_csv.seek(0)
            return extract_bootstrap_nodes(temp_csv.name)
        except subprocess.CalledProcessError as e:
            print(f"Error: TShark command failed with exit code {e.returncode}")
            return []

def main(argv):
    input_path = None
    input_type = None
    init_mode = False

    for i in range(len(argv)):
        if argv[i] == '-csv' or argv[i] == '-pcap':
            input_type = argv[i]
            input_path = argv[i + 1]
        elif argv[i] == '-init':
            init_mode = True

    if not input_path or not input_type:
        print("Error: No input path provided. Use -csv <path> or -pcap <path> to specify the path.")
        return

    if init_mode:
        if input_type == '-csv':
            bootstrap_nodes = extract_bootstrap_nodes(input_path)
        elif input_type == '-pcap':
            bootstrap_nodes = process_pcap(input_path)

        print("Bootstrap nodes (sorted by port):")
        for node in bootstrap_nodes:
            print(f"{node[0]}:{node[1]}")

if __name__ == "__main__":
    main(sys.argv[1:])