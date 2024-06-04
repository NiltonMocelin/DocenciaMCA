#01/07
#algoritmo para separa uma base de dados de um tipo de aplicação em fluxos - cada fluxo unilateral em um arquivo.

#entrada: arquivo pcap subflow com pacotes dentro do intervalo idle_timeout settado em separaSubFluxos.py
#saida: arquivo .csv com as features listadas + applabel

#https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
########            features (apenas estamos interessados em features one-way):
#  Protocol,Flow.Duration (diferenca de tempo entre o primeiro pacote e o ultimo do bloco),Total.Length.of.Fwd.Packets.Packets,Fwd.Packet.Length.Max,
# Fwd.Packet.Length.Min,Fwd.Packet.Length.Mean,Fwd.Packet.Length.Std,
# Flow.Bytes.s,Flow.Packets.s,Flow.IAT.Mean,Flow.IAT.Std,Flow.IAT.Max,Flow.IAT.Min,Fwd.IAT.Total,Fwd.IAT.Mean,Fwd.IAT.Std,Fwd.IAT.Max,Fwd.IAT.Min,
# Fwd.PSH.Flags,Fwd.URG.Flags,Fwd.Header.Length,Fwd.Packets.s,Packet.Length.Variance,FIN.Flag.Count,SYN.Flag.Count,RST.Flag.Count,PSH.Flag.Count,
# ACK.Flag.Count,URG.Flag.Count,CWE.Flag.Count,ECE.Flag.Count,Down.Up.Ratio,Average.Packet.Size,Avg.Fwd.Segment.Size,Fwd.Header.Length.1,
# Fwd.Avg.Bytes.Bulk,Fwd.Avg.Packets.Bulk,Fwd.Avg.Bulk.Rate,Subflow.Fwd.Packets,Subflow.Fwd.Bytes,Init_Win_bytes_forward,act_data_pkt_fwd,
# min_seg_size_forward,Active.Mean,Active.Std,Active.Max,Active.Min,Idle.Mean,Idle.Std,Idle.Max,Idle.Min
# Label,L7Protocol,ProtocolName


# lista de portas de serviço IANA: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers


# obs: se atentar a necessidade de normalizar os valores

import argparse
import os
import sys

# from scapy.utils import RawPcapReader
# from scapy.utils import rdpcap
# from scapy.all import *
from scapy.utils import rdpcap, RawPcapReader, RawPcapWriter
from scapy.all import IP, UDP, TCP, Padding, Raw

import math


#valores maximos para normalizacao

#10s (idle_timeout)
# block_size * idle_timeout
# duracao_maxima = 0
idle_timeout = 10.0
#mtu = 1500
# tamanho_maximo_pkt = 1500
tamanho_maximo_pkt =0.0

# tamanho_maximo_soma = 1500 * block_size
tamanho_maximo_soma = 0.0

# desviopadrao_maximo = tamanho_maximo_pkt
desviopadrao_maximo = 0.0

# pkts_maiormenor_qamedia_maximo = block_size
pkts_maiormenor_qamedia_maximo = 0.0

# payload_maximo = tamanho_maximo_pkt 
payload_maximo=0.0

# IAT_maximo = idle_timeout
IAT_maximo= 0.0

# IAT_soma_maximo = duracao_maxima
IAT_soma_maximo = 0.0

# flags_max = block_size
flags_max=0.0

#header max = 40bytes -> pacote maximo = 1460bytes
header_max = 40.0

#tamanho max porta 65535
porta_max = 65535.0

max_pktsporseg = 10000.0

tamanho_max_bloco = 0.0

#obs para desvio padrao o maior valor é metade da media, pois eh a distancia, e se a media for o maior valor, entao o std_max = maior/2

#[feito] mudar payload para [UDP].payload e [TCP].payload

# 44 features - one way

#transporte - tcp/udp
def get_protocol(bloco):
    if(bloco[0].haslayer(UDP)):
        # return '17'
        return '0'
    elif(bloco[0].haslayer(TCP)):
        # return '6'
        return '1'
    #aqui nao era pra acontecer !!
    return '-1'

def get_dport(bloco):
    if(bloco[0].haslayer(UDP)):
        # bloco[0].getlayer(UDP).dport
        retorno = bloco[0].getlayer(UDP).dport/porta_max
        return str(retorno)
    elif(bloco[0].haslayer(TCP)):
        # bloco[0].getlayer(TCP).dport
        retorno = bloco[0].getlayer(TCP).dport/porta_max
        return str(retorno)
    return '0'

def get_subflow_duration(bloco):
    timestampi = bloco[0].time
    timestampf = bloco[-1].time
    retorno = timestampf-timestampi
    retorno = retorno/duracao_maxima
    return str(retorno)

def get_packet_length_sum(bloco):
    soma = 0.0
    for i in bloco:
        soma+= len(i)
    retorno = soma/(tamanho_maximo_pkt*tamanho_max_bloco)
    return str(retorno)

def get_packet_length_max(bloco):
    maior = 0
    for pkt in bloco:
        if len(pkt)> maior:
            maior = len(pkt)
    retorno = maior/tamanho_maximo_pkt
    return str(retorno)

def get_packet_length_min(bloco):
    menor = len(bloco[0])
    for pkt in bloco:
        if len(pkt) < menor:
            menor = len(pkt)
    
    retorno = menor/tamanho_maximo_pkt
    print("menor {} tam maximo {} retorno {}".format(menor,tamanho_maximo_pkt, retorno))
    return str(retorno)

def get_packet_per_second(bloco):
    duracao = bloco[-1].time - bloco[0].time
    retorno = len(bloco)/float(duracao)
    retorno = retorno / max_pktsporseg
    return str(retorno)

def get_1st_quartile_packet_length(bloco):
    #ordenar os valores
    #len(valores) * (1/4) = posicao do valor, para o qual representa o valor maior que os 25% primeiros valores
    lista_len = []
    for pkt in bloco:
        lista_len.append(len(pkt))
    lista_ordenada = sorted(lista_len, key = lambda x:float(x))
    quartil = int(len(lista_len) * 0.25)
    retorno = lista_ordenada[quartil]
    retorno = retorno / tamanho_maximo_pkt
    return str(retorno)

def get_3rd_quartile_packet_length(bloco):
    #ordenar os valores
    #len(valores) * (3/4) = posicao do valor, para o qual representa o valor maior que os 25% primeiros valores
    lista_len = []
    for pkt in bloco:
        lista_len.append(len(pkt))
    lista_ordenada = sorted(lista_len, key = lambda x:float(x))
    quartil = int(len(lista_len) * 0.75)
    retorno = lista_ordenada[quartil]
    retorno = retorno / tamanho_maximo_pkt
    return str(retorno)

#media
def get_packet_length_mean(bloco):
    soma = 0.0
    tamanho = len(bloco)
    for pkt in bloco:
        soma += len(pkt)
    retorno = soma/tamanho
    retorno = retorno / tamanho_maximo_pkt
    return str(retorno)

#mediana
def get_packet_length_median(bloco):
    lista_len = []
    tamanho_lista = len(lista_len)
    for pkt in bloco:
        lista_len.append(len(pkt))
    
    lista_ordenada = sorted(lista_len, key = lambda x:float(x))
    meio = tamanho_lista/2 -1
    if(int(tamanho_lista % 2) != 0):     
        retorno = lista_ordenada[int(meio)]
        retorno = retorno / tamanho_maximo_pkt
        return str(retorno)
    retorno = (lista_ordenada[int(meio)] + lista_ordenada[int(meio + 1)])/2
    retorno = retorno / tamanho_maximo_pkt
    return str(retorno)

#desvio padrao Down.Up.Ratio
def get_packet_length_std(bloco):

    #media
    soma = 0.0
    tamanho = len(bloco)
    for pkt in bloco:
        soma += len(pkt)
    retorno = soma/tamanho

    media = retorno
    soma = 0.0
    for pkt in bloco:
        val = len(pkt) - media
        soma += val * val
    retorno = math.sqrt(soma/len(bloco))
    retorno = retorno / (tamanho_maximo_pkt/2)
    return str(retorno)

#quantidade de pacotes que sao maiores que a media
def get_packets_above_media(bloco):
        #media
    soma = 0.0
    tamanho = len(bloco)
    for pkt in bloco:
        soma += len(pkt)
    retorno = soma/tamanho

    media = retorno

    contador = 0
    for pkt in bloco:
        if len(pkt)>media:
            contador +=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_packets_below_media(bloco):
        #media
    soma = 0.0
    tamanho = len(bloco)
    for pkt in bloco:
        soma += len(pkt)
    retorno = soma/tamanho

    media = retorno

    contador = 0
    for pkt in bloco:
        if len(pkt)<=media:
            contador +=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

#payload -- adicinado por mim - ver se faz sentido, pq aplicações podem mandar quantidades de dados bem variaveis
def get_payload_length_sum(bloco):
    #ignorando padding - pois eh usado em situacoes especificas e geralmente adiciona poucos bytes
    soma = 0
    for pkt in bloco:
        if pkt.haslayer(TCP):
            soma += len(pkt[TCP].payload)
        else:
            soma += len(pkt[UDP].payload)
    retorno = soma/tamanho_maximo_soma
    return str(retorno)

def get_payload_length_min(bloco):
    menor = len(bloco[0])
    for pkt in bloco:
        payload = menor
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        if menor > payload:
            menor = payload
    retorno = menor/payload_maximo
    return str(retorno)

def get_payload_length_max(bloco):
    maior = 0
    for pkt in bloco:
        payload = maior
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        if maior < payload:
            maior = payload
    retorno = maior/payload_maximo
    return str(retorno)

def get_payload_length_mean(bloco):
    soma = 0
    for pkt in bloco:
        if pkt.haslayer(TCP):
            soma += len(pkt[TCP].payload)
        else:
            soma += len(pkt[UDP].payload)

    contador = len(bloco)
    retorno = soma/contador
    retorno = retorno / payload_maximo
    return str(retorno)

def get_payload_length_std(bloco):
    
    #media
    soma = 0
    for pkt in bloco:
        if pkt.haslayer(TCP):
            soma += len(pkt[TCP].payload)
        else:
            soma += len(pkt[UDP].payload)

    contador = len(bloco)
    media = soma/contador

    soma = 0.0
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        val = payload - media
        soma += val*val
    retorno = math.sqrt(soma/len(bloco))
    retorno = retorno / (payload_maximo)
    return str(retorno)

# of pkts whose payload lengths are below 128
def get_pkts_payload_bellow_128(bloco):
    contador = 0 
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        if(payload < 128):
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_pkts_payload_between_128_1024(bloco):
    contador = 0 
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        if(payload >= 128 and payload < 1024):
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

# pld_bin_inf: # of pkts whose payload lengths are above 1024
def get_pkts_payload_above_1024(bloco): 
    contador = 0 
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        if(payload >= 1024):
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_1st_quartile_payload_length(bloco):
    #ordenar os valores
    #len(valores) * (1/4) = posicao do valor, para o qual representa o valor maior que os 25% primeiros valores
    lista_payload = []
    
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        lista_payload.append(payload)
    quartil = int(len(lista_payload) * 0.25)
    lista_ordenada = sorted(lista_payload, key = lambda x:float(x))
    retorno = lista_ordenada[quartil]/payload_maximo
    return str(retorno)


def get_3rd_quartile_payload_length(bloco):
    #ordenar os valores
    #len(valores) * (1/4) = posicao do valor, para o qual representa o valor maior que os 25% primeiros valores
    lista_payload = []
    
    for pkt in bloco:
        payload = 0
        if pkt.haslayer(TCP):
            payload = len(pkt[TCP].payload)
        else:
            payload = len(pkt[UDP].payload)
        lista_payload.append(payload)
    quartil = int(len(lista_payload) * 0.75)
    lista_ordenada = sorted(lista_payload, key = lambda x:float(x))

    retorno = lista_ordenada[quartil]/payload_maximo
    return str(retorno)

def get_IAT_min(bloco):
    minimo = 5000.0
    #comecar do segundo pacote no bloco
    for i in range(1,len(bloco)):
        tempo =  bloco[i].time - bloco[i-1].time
        if tempo < minimo:
            minimo = tempo
    if(minimo == 5000.0):
        return '0'
    retorno = minimo/idle_timeout
    return str(retorno)

def get_IAT_max(bloco):
    maximo = 0.0
    #comecar do segundo pacote no bloco
    for i in range(1,len(bloco)):
        tempo =  bloco[i].time - bloco[i-1].time
        if tempo > maximo:
            maximo = tempo
    retorno = maximo/idle_timeout
    return str(retorno)

def get_IAT_sum(bloco):
    soma = 0.0
    for i in range(1,len(bloco)):
        tempo =  bloco[i].time - bloco[i-1].time
        soma += tempo
    retorno = soma/(idle_timeout*tamanho_max_bloco)
    return str(retorno)

def get_IAT_mean(bloco):
    soma = 0.0
    #excluir o primeiro pacote
    contador = len(bloco)
    for i in range(1,contador):
        tempo =  bloco[i].time - bloco[i-1].time
        soma += tempo    

    if contador -1 == 0:
        return '0'

    retorno = soma/(contador-1)
    returno = retorno / idle_timeout
    return str(retorno)

def get_pkts_IAT_above_mean(bloco):
    
    #media
    soma = 0.0
    #excluir o primeiro pacote
    contador = len(bloco)
    for i in range(1,contador):
        tempo =  bloco[i].time - bloco[i-1].time
        soma += tempo    

    if contador -1 == 0:
        return '0'

    media = soma/(contador-1)

    size = len(bloco)
    contador=0
    for i in range(1,size):
        tempo =  bloco[i].time - bloco[i-1].time
        if tempo > media:
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_pkts_IAT_below_mean(bloco):
    
    #media
    soma = 0.0
    #excluir o primeiro pacote
    contador = len(bloco)
    for i in range(1,contador):
        tempo =  bloco[i].time - bloco[i-1].time
        soma += tempo    

    if contador -1 == 0:
        return '0'

    media = soma/(contador-1)

    size = len(bloco)
    contador=0
    for i in range(1,size):
        tempo =  bloco[i].time - bloco[i-1].time
        if tempo <= media:
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_IAT_std(bloco):#std = sumi->n ( vi - vm )*2/N
    
    #media
    soma = 0.0
    #excluir o primeiro pacote
    contador = len(bloco)
    for i in range(1,contador):
        tempo =  bloco[i].time - bloco[i-1].time
        soma += tempo    

    if contador -1 == 0:
        return '0'

    media = soma/(contador-1)

    size = len(bloco)
    soma = 0.0

    for i in range(1,size):
        iat = bloco[i].time - bloco[i-1].time
        calc = iat - media
        soma += calc * calc
    retorno = math.sqrt(soma/(size-1))
    retorno = retorno / (IAT_maximo)
    return str(retorno)

def get_1st_quartile_IAT(bloco):
    tamanho = len(bloco)
    lista_iat = []
    for i in range(1,tamanho):
        tempo =  bloco[i].time - bloco[i-1].time
        lista_iat.append(tempo) 

    tamanho = len(lista_iat)
    quartil = int(tamanho * 0.25)
    lista_ordenada = sorted(lista_iat, key = lambda x:float(x))
    retorno = lista_ordenada[quartil]/idle_timeout
    return str(retorno)

def get_3rd_quartile_IAT(bloco):
    tamanho = len(bloco)
    lista_iat = []
    for i in range(1,tamanho):
        tempo =  bloco[i].time - bloco[i-1].time
        lista_iat.append(tempo) 

    tamanho = len(lista_iat)
    quartil = int(tamanho * 0.75)
    lista_ordenada = sorted(lista_iat, key = lambda x:float(x))
    retorno = lista_ordenada[quartil]/idle_timeout
    return str(retorno)

#tcp header
def get_tcp_psh_flags_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'P' in str(pkt[TCP].flags) :
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_tcp_urg_flags_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'U' in str(pkt[TCP].flags) :
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_tcp_flag_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        contador += len(str(pkt[TCP].flags))

    print("flags: {}".format(contador))
    #cada pacote pode ter 8 flags
    retorno = contador/(tamanho_max_bloco*8)
    return str(retorno)

def get_tcp_syn_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'S' in str(pkt[TCP].flags) :
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_tcp_fin_flags_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'F' in str(pkt[TCP].flags) :
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_tcp_rst_flags_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'R' in str(pkt[TCP].flags) :
            contador+=1
    retorno = contador/tamanho_max_bloco
    return str(retorno)

def get_tcp_ack_flags_sum(bloco):
    if not bloco[0].haslayer(TCP):
        return '0'
    contador=0
    for pkt in bloco:
        if 'A' in str(pkt[TCP].flags) :
            contador+=1

    retorno = contador/tamanho_max_bloco
    return str(retorno)

#esses dois são para controle de congestionamento - cwe e ece
# def get_tcp_cwe_flags_sum(bloco):
    
#     return ''

# def get_tcp_ece_flags_sum(bloco):
#     return ''

def get_header_length_sum(bloco):
    header_s = 0.0
    for pkt in bloco:
        if (pkt.haslayer(TCP)) :
            header_s += len(pkt[TCP]) - len(pkt[TCP].payload)
        else:
            header_s += len(pkt[UDP]) -  len(pkt[UDP].payload)
    retorno = header_s/(header_max*tamanho_max_bloco)
    return str(retorno)

def get_header_length_mean(bloco):
    #nao pode chamar a funcao pois ela normaliza o valor entre 0..1 -- implementar aqui dentro
    header_s = 0.0
    for pkt in bloco:
        if (pkt.haslayer(TCP)) :
            header_s += len(pkt[TCP]) - len(pkt[TCP].payload)
        else:
            header_s += len(pkt[UDP]) -  len(pkt[UDP].payload)
    
    retorno = header_s/len(bloco)

    # print("media header {}".format(header_s))
    retorno = retorno/header_max
    return str(retorno)

def get_header_length_std(bloco):
    #media
    header_s = 0.0
    for pkt in bloco:
        if (pkt.haslayer(TCP)) :
            header_s += len(pkt[TCP]) - len(pkt[TCP].payload)
        else:
            header_s += len(pkt[UDP]) -  len(pkt[UDP].payload)
    
    media = header_s/len(bloco)

    soma = 0.0
    for pkt in bloco:

        if( pkt.haslayer(TCP) ):
            header_s = len(pkt[TCP]) - len(pkt[TCP].payload) - media
        else:
            header_s = len(pkt[UDP]) - len(pkt[UDP].payload) - media

        soma += header_s * header_s
    retorno = math.sqrt(soma/len(bloco))
    retorno = retorno/(header_max)
    return str(retorno)

#o que eh isso msm? -- informa quantos pacotes sao enviados para entao receber uma confirmacao -- aparentemente cada pacote leva um valor de janela, entao usar para ver no que da
def get_window_size_sum(bloco):
    # packet1[TCP].window
    if not bloco[0].haslayer(TCP):
        return '0'
    soma = 0
    for pkt in bloco:
        soma += pkt[TCP].window
    retorno = soma/(tamanho_max_bloco*65535)
    return str(retorno)

def get_window_size_mean(bloco):
    # packet1[TCP].window
    if not bloco[0].haslayer(TCP):
        return '0'
    soma = 0
    for pkt in bloco:
        soma += pkt[TCP].window
    retorno = soma/len(bloco)
    retorno = retorno /65535
    return str(retorno)

def get_window_size_std(bloco):
    # packet1[TCP].window
    if not bloco[0].haslayer(TCP):
        return '0'

    #media
    soma = 0
    for pkt in bloco:
        soma += pkt[TCP].window
    retorno = soma/len(bloco)

    media = retorno

    soma = 0.0
    for pkt in bloco:
        val = (pkt[TCP].window - media)
        soma += val * val 
    retorno = math.sqrt(soma/len(bloco))
    retorno = retorno / (65535)
    return str(retorno)


#pegar um subflow inteiro - retorna alguma informacao que representa a largura de banda do subflow (media?, mediana?, maior?)
def calcularLarguraBanda_subflow(bloco):

    #media em bytes
    soma = 0.0
    for i in bloco:
        soma+= len(i)

    #em segundos
    duracao = float(bloco[-1].time - bloco[0].time)

    if duracao == 0:
        return '0'

    #bytes/segundo
    lbanda = soma/duracao
    retorno = lbanda / 1000
    #normalizar em 15mbps
    retorno = retorno / 15000
    #obter em kbps
    return str(retorno)


def process_pcap(file_name, block_size, app_label):
    block_size = int(block_size)

    print('Opening {}...'.format(file_name))

    pcaps = rdpcap(file_name)

    #criando arquivo csv com mesmo nome do arquivo pcap
    csv_file = file_name.split(".pcap")[0] + '.csv'

    print("Nome aquivo .csv: {}".format(csv_file))

    #abrir concatenar e criar se nao existir
    file = open(csv_file, 'a+')

#47
    file.write("cont,pkts,class,proto,dport,lbanda,duracao,pkt_soma_tam,pkt_maior_tam,pkt_menor_tam,\
pkts_por_seg,1stq_pkt_tam,3rdq_pkt_tam,pkt_tam_media,pkt_tam_mediana,pkt_tam_std,\
pkts_maiores_media,pacotes_menores_media,payload_soma,payload_menor,payload_maior,payload_media,\
payload_std,payload_menor_128,payload_entre128_1024,payload_maior_1024,1stq_payload_tam,\
3rdq_payload_tam,IAT_menor,IAT_maior,IAT_soma,IAT_media,IAT_maiores_media,IAT_menores_media,\
IAT_std,1stq_IAT,3rdq_IAT,tcp_push_flags,tcp_urg_flags,tcp_syn_flags,tcp_fin_flags,tcp_rst_flags,\
tcp_ack_flags,tcp_flags,header_tam_soma,header_tam_media,header_tam_std\n")

    #bloco de pacotes
    bloco = []
    
    blocos_total = 0
    contador_bloco = 0
    classe = app_label

    for pkt in pcaps:

        #estrategia, ler pacotes do bloco e colocar em um buffer (10/20/30 pacotes)
        #processar as features do bloco
        #salvar as features do bloco em uma linha do arquivo csv
        #flush
        #repetir

        if(pkt.haslayer(IP) == False and pkt.haslayer(UDP)== False and pkt.haslayer(TCP)== False):
            continue

        bloco.append(pkt)
        contador_bloco+=1

        print('contadorblock {}, block_size {}'.format(contador_bloco, block_size))

        if ( contador_bloco == block_size):
            contador_bloco = 0

            print("ret: {}".format(get_packet_length_min(bloco)))

            linha = str(blocos_total) +','+ str(len(bloco))+','+classe +',' +get_protocol(bloco)+ ','+get_dport(bloco)+','+\
                    calcularLarguraBanda_subflow(bloco)+ ','+get_subflow_duration(bloco)+ ','+ \
                    get_packet_length_sum(bloco)+ ','+get_packet_length_max(bloco)+ ','+ \
                    get_packet_length_min(bloco)+ ','+get_packet_per_second(bloco)+ ','+ \
                    get_1st_quartile_packet_length(bloco)+ ','+get_3rd_quartile_packet_length(bloco)+ ','+ \
                    get_packet_length_mean(bloco)+ ','+get_packet_length_median(bloco)+ ','+ \
                    get_packet_length_std(bloco)+ ','+get_packets_above_media(bloco)+ ','+ \
                    get_packets_below_media(bloco)+ ','+get_payload_length_sum(bloco)+ ','+ \
                    get_payload_length_min(bloco)+ ','+get_payload_length_max(bloco)+ ','+ \
                    get_payload_length_mean(bloco)+ ','+get_payload_length_std(bloco)+ ','+ \
                    get_pkts_payload_bellow_128(bloco)+ ','+get_pkts_payload_between_128_1024(bloco)+ ','+ \
                    get_pkts_payload_above_1024(bloco)+ ','+get_1st_quartile_payload_length(bloco)+ ','+ \
                    get_3rd_quartile_payload_length(bloco)+ ','+get_IAT_min(bloco)+ ','+ \
                    get_IAT_max(bloco)+ ','+get_IAT_sum(bloco)+ ','+get_IAT_mean(bloco)+ ','+ \
                    get_pkts_IAT_above_mean(bloco)+ ','+get_pkts_IAT_below_mean(bloco)+ ','+ \
                    get_IAT_std(bloco)+ ','+get_1st_quartile_IAT(bloco)+ ','+ \
                    get_3rd_quartile_IAT(bloco)+ ','+get_tcp_psh_flags_sum(bloco)+ ','+ \
                    get_tcp_urg_flags_sum(bloco)+ ','+ \
                    get_tcp_syn_sum(bloco)+ ','+get_tcp_fin_flags_sum(bloco)+ ','+ \
                    get_tcp_rst_flags_sum(bloco)+ ','+get_tcp_ack_flags_sum(bloco)+ ','+ \
                    get_tcp_flag_sum(bloco)+ ','+ \
                    get_header_length_sum(bloco)+ ','+ \
                    get_header_length_mean(bloco)+ ','+ get_header_length_std(bloco)+'\n'
            
            blocos_total +=1
                
            bloco.clear()
            
            file.write(linha)

    file.close()
            


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--applabel', metavar='<[string] aplication label (ex. fb_video)>',
                        help='[string] aplication label (ex. fb_video)', required=True)
    parser.add_argument('--blocksize', metavar='<[integer] amount of packets to get the features counted -> 0 = all>',
                        help='[integer] amount of packets to get the features counted -> 0 = all', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    block_size = args.blocksize

    app_label = args.applabel

    #valores para a normalizacao [0..1], obs alguns vao passar de 1 pq alguns pacotes estao estranhos na base
    #mtu = 1500
    tamanho_maximo_pkt =1500.0
    
    tamanho_max_bloco = float(block_size)

    #idle_timeout 10s
    idle_timeout = 10.0

    # tamanho_maximo_soma = tamanho_maximo_pkt * block_size
    tamanho_maximo_soma = tamanho_maximo_pkt * tamanho_max_bloco

    # desviopadrao_maximo = tamanho_maximo_pkt
    desviopadrao_maximo = tamanho_maximo_pkt

    # pkts_maiormenor_qamedia_maximo = tamanho_max_bloco
    pkts_maiormenor_qamedia_maximo = tamanho_max_bloco

    # payload_maximo = tamanho_maximo_pkt 
    payload_maximo=tamanho_maximo_pkt

    # IAT_maximo = idle_timeout = 10s
    IAT_maximo= idle_timeout

    # tamanho_max_bloco * idle_timeout
    duracao_maxima = tamanho_max_bloco * idle_timeout

    # IAT_soma_maximo = duracao_maxima
    IAT_soma_maximo = duracao_maxima

    # flags_max = tamanho_max_bloco
    flags_max=tamanho_max_bloco

    process_pcap(file_name, block_size, app_label)
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