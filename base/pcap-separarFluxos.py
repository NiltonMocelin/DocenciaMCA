#algoritmo para separa uma base de dados de um tipo de aplicação em fluxos - cada fluxo unilateral em um arquivo.

#https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html

#entrada: arquivo pcap completo
#saida: arquivos pcap separados por par ip_s, ip_d, portd

import argparse
import os
import sys

# from scapy.utils import RawPcapReader
# from scapy.utils import rdpcap
# from scapy.all import *
from scapy.utils import rdpcap, RawPcapReader, RawPcapWriter
from scapy.all import IP, UDP, TCP

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    pcaps = rdpcap(file_name)

    portd = ''
    newfile_name = ''
    
    for pkt in pcaps:

        if(pkt.haslayer(IP) == False):
            continue

        ip_pkt = pkt.getlayer(IP)
        
        #ip eh string
        # print(isinstance(ip_pkt.src, str))

        if( pkt.haslayer(UDP) ):
            #port eh inteiro
            # print(pkt.getlayer(UDP).dport)
            portd = str(pkt.getlayer(UDP).dport)
            newfile_name = 'udp'
        elif (pkt.haslayer(TCP)):
            # print(pkt.getlayer(TCP).dport)
            portd = str(pkt.getlayer(TCP).dport)
            newfile_name = 'tcp'
        else:
            #pular pacote
            continue

        newfile_name += '_' + ip_pkt.src + "_" + ip_pkt.dst + "_" +portd

        print(newfile_name)
        # pktdump = RawPcapWriter(newfile_name +".pcap", append=True, sync=True)
        pktdump = RawPcapWriter(newfile_name +".pcap", append=True)
        # pktdump = wrpcap(newfile_name, pkt, append=True)

        pktdump.write(pkt)
        # pktdump.close()
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)

# summary() displays a list of summaries of each packet
# nsummary() same as previous, with the packet number
# conversations() displays a graph of conversations
# show() displays the prefered representation (usually
# nsummary())
# filter() returns a packet list filtered with a lambda function
# hexdump() returns a hexdump of all packets
# hexraw() returns a hexdump of the Raw layer of all packets
# padding() returns a hexdump of packets with padding
# nzpadding() returns a hexdump of packets with non-zero
# padding
# plot() plots a lambda function applied to the packet list
# make table() displays a table according to a lambda function
# Philippe BIONDI Network packet manipul



#printar tempo de chegada de um pacote

# print('First packet in connection: Packet #{} {}'.
#           format(first_pkt_ordinal,
#                  printable_timestamp(first_pkt_timestamp,
#                                      first_pkt_timestamp_resolution)))

# import time

# def printable_timestamp(ts, resol):
#     ts_sec = ts // resol
#     ts_subsec = ts % resol
#     ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
#     return '{}.{}'.format(ts_sec_str, ts_subsec)