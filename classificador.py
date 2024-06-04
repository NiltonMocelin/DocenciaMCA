from sklearn.ensemble import RandomForestClassifier
import joblib

from processador_pacotes import processar_buffer, processar_pacote

QTD_PACOTES = 15

class ClassificadorRF:
	def __init__(self):
		#importando modelo de classificacao Random Forest    
		self.rf_model = joblib.load("./random_forest.joblib")
		#importar o arquivo de configuracao do treinamento
		#self.rfmodel
		print("[RF] Classificador criado...")
		
		#dicionario de buffers -> "ipsrc_ipdst_proto_srcport_dstport" : ["PacoteProcessado1", "PacoteProcessado2"]
		self.buffers = {}
		
	def classificar(self, fluxo_id):
		
		#verificar se o fluxo id existe e o buffer ja tem a qtd de pacotes necessaria
		if fluxo_id in self.buffers:
			
			if len(self.buffers[fluxo_id]) == QTD_PACOTES:
				
				#remove o buffer
				#processa todos os pacotes e gerar uma entrada de classificacao
				fluxo_dados_processado = processar_buffer(self.buffers.pop(fluxo_id))
				
				#classifica e retorna
				print("[RF] Classificando um fluxo...")
				return self.rf_model.predict(fluxo_dados_processado)
		
		#buffer nao existe ou nao completou a qtd de pacotes proposta
		print("[RF] Erro ao classificar fluxo...")
		return None
				
		

#retorna false se ainda nao atingiu o numero de pacotes
#retorna true se ja atingiu -> classificar
	def armazenarPacote(self, fluxo_id, timestamp, pacote) -> bool:
		#rotina
		#verificar se ja existe um buffer desse fluxos
		if fluxo_id in self.buffers:
		
			# se ja existe
			#processa o pacote e adiciona no buffer
			self.buffers[fluxo_id].append( (timestamp, processar_pacote(pacote)) )
			return True
				
		# se nao existir ainda -> cria o buffer, processa o pacote e adiciona no buffer
		self.buffers[fluxo_id] = []
		return False
