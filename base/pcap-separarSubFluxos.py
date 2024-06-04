#algoritmo para separar fluxos em subfluxos ativos - pacotes que possuem tempo entre chegadas que respeitam o idle_timeout do framework FLOWPRI-sdn

#https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html

#entrada: um pcap com pacotes de apenas um par ip_s, ip_d, portd
#saida: varios pcaps com pacotes com tempo entre chegadas respeitando o idle_timeout

import argparse
import os
import sys

from scapy.utils import rdpcap, RawPcapReader, RawPcapWriter
from scapy.all import IP, UDP, TCP
# from scapy.all import *

def process_pcap(file_name):

    # definindo timeout de 10s 
    idle_timeout = 10

    #dicionario (ips, ipd, portd) = contador de subflow
    par_contador = {}

    #timestamp pacote anterior - para decidir se precisa colocar em outro subflow
    pkt_anterior_timestamp = None

    print('Opening {}...'.format(file_name))

    pcaps = rdpcap(file_name)
    
    for pkt in pcaps:

        if(pkt.haslayer(IP) == False): # and (pkt.haslayer(UDP) == False or pkt.haslayer(TCP) == False)) :
            continue

        ip_pkt = pkt.getlayer(IP)
        ips = ip_pkt.src
        ipd = ip_pkt.dst
        portd = ''
        newfile_name = 'sub_'

        if( pkt.haslayer(UDP) ):
            #port eh inteiro
            # print(pkt.getlayer(UDP).dport)
            portd = str(pkt.getlayer(UDP).dport)
            newfile_name += 'udp_'
        elif (pkt.haslayer(TCP)):
            # print(pkt.getlayer(TCP).dport)
            portd = str(pkt.getlayer(TCP).dport)
            newfile_name += 'tcp_'
        else:
            continue

        #isso ja resolve para o primeiro pacote
        if (ips,ipd,portd) not in par_contador:
            par_contador[ (ips,ipd,portd) ] = 0

        timestamp = float(pkt.time)

        #se a diferenca de tempo for maior que o idle_timeout -> colocar em outro subflow(arquivo)
        if(pkt_anterior_timestamp != None):
            if (timestamp - pkt_anterior_timestamp > idle_timeout):
                par_contador[ (ips,ipd,portd) ] += 1

        #pacote atual eh o novo anterior
        pkt_anterior_timestamp = timestamp

        newfile_name += ip_pkt.src + "_" + ip_pkt.dst + "_" + portd +'_'+str(par_contador[ (ips,ipd,portd) ])
  
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