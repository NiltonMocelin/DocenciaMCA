# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp, tcp
from ryu.lib.packet import ether_types

import json
from classificador import ClassificadorRF as rfclassificador


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        self.mac_to_ip = {}
        
        self.mac_to_ip['default'] = 'eth0'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

	#criando regra meter
    def addRegraM(self, meter_id, banda):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #criando meter bands
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=10)]#e esse burst_size ajustar?
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
        datapath.send_msg(req)
        return

	#add regra tabela FORWARD
    def addRegraF(self, datapath, ip_src, ip_dst, out_port, src_port, dst_port, proto, meter_id):
        """ Parametros:
        ip_ver:str
        ip_src: str
        ip_dst: str
        ip_dscp: int
        out_port: int
        src_port: int
        dst_port: int 
        proto: str
        meter_id: int 
        """
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_src, ipv4_dst=ip_dst)
             
        #tratamento especial para este tipo de trafego
        if proto ==in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port)
        elif proto == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, udp_src = src_port, udp_dst=dst_port)

        actions = [parser.OFPActionSetQueue(fila), parser.OFPActionOutput(out_port)]
        
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if meter_id != None:
			inst.append( parser.OFPInstructionMeter(meter_id=meter_id) )
 
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)

        datapath.send_msg(mod)


	def injetar_pacote(self, porta_saida, porta_origem, datapath, msg, dados):
			
		actions = [datapath.ofproto_parser.OFPActionOutput(porta_saida)]
		
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=porta_origem, actions=actions, data=dados)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
                              
        msg = ev.msg
        
        #print(json.dumps(ev.msg.to_jsondict(), ensure_ascii=True, indent=3, sort_keys=True))
        
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

		
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            
        ##############
        
        dst = eth.dst #MAC
        src = eth.src
		
		ip_src = None
		ip_dst = None
		
		ip_ver = None
		
		proto = None
		
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        
        if pkt_ipv4:
            #print("\nPacote IPv4: ")
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_ver = 'ipv4'
        
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto='tcp'
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto='udp'
            
            
        #aprender ip e mac
        if src not in self.mac_to_port:
			self.mac_to_port[src] = in_port
		
		if ip_src not in self.mac_to_ip:
			self.mac_to_ip[src] = ip_src
        
        #para onde este pacote deve ser enviado no switch (acao)
        #duas possibilidades: (1)ou o pacote saiu do host para fora do dominio -> eth0
        #(2)ou o pacote esta chegando em direcao ao dominio -> s1-eth1
        
        out_port = 'eth0'
        
        if dst in self.mac_to_ip:
			out_port = self.mac_to_ip[dst]
        else
			out_port = self.mac_to_ip['default']
        
       
		#verificando se eh um pacote valido para a classificacao
		if ip_src != None and proto!=None:
			fluxo_id = ip_src+'-'+ip_dst+'-'+proto+'-'+src_port+'-'+ dst_port
			
			fluxo_completo_para_classificacao = rfclassificador.armazenarPacote(fluxo_id, timestamp, pkt)
			
			if fluxo_completo_para_classificacao :
				classe = rfclassificador.classificar(fluxo_id)
				
				if classe == 'QoS':
					#criar meter band
					self.addRegraM(meter_id = src_port, banda = str(1024*5)) # 5Mbps
					#criar flow rule
					self.addRegraF(datapath, ip_src, ip_dst, out_port, src_port, dst_port, proto, meter_id):
				else: #Best-effort
					self.addRegraM(meter_id = src_port, banda = str(1024)) # 1Mbps
					#criar flow rule
					self.addRegraF(datapath, ip_src, ip_dst, out_port, src_port, dst_port, proto, meter_id):
								
		#injetando o pacote em um switch e manualmente definir a acao sem criar regra de fluxo ate chegarem 15 pacotes
		#injetar o pacote no mesmo switch que gerou o evento
		#duas possibilidades: (1)ou o pacote saiu do host para fora do dominio -> eth0
		#(2)ou o pacote esta chegando em direcao ao dominio -> s1-eth1
		injetar_pacote(out_port, in_port, datapath, msg, msg.match['data'])		

			
		##############
