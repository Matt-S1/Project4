import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    count = 0
    interesting_packet_count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        src_ip = 0
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        #interesting_packet_count += 1

        # displays the ip address of the src  of the packet
        # info on TCP flags from https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy
        if IP in ip_pkt:
            src_ip = ip_pkt.src

            if ether_pkt[TCP].window <= 1024 and ether_pkt['TCP'].flags == 0x02:
                print(
                    f'Possible TCP SYN / stealth scan going to {ip_pkt.dst} from {src_ip}')
                interesting_packet_count += 1

    print(f'{file_name} contains {count} packets ({interesting_packet_count} packets were counted).')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to prase', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)
