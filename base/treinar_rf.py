#nao fiz mas eh combinar os codigos la q ja estao prontos 

import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

data = pd.read_csv("base-balanceada.csv")

classes = data['class'].tolist()

#Escolher as colunas serao utilizadas como dados
data = data.drop(columns=['cont','pkts','class', 'tcp_urg_flags','dport'])#,'IAT_std', , 'tcp_rst_flags','tcp_syn_flags', 'tcp_fin_flags','header_tam_std', 'tcp_push_flags'])

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay
import time


#Separando a base de dados em 70% 30%
X_train, X_test, y_train, y_test = train_test_split(data, classes,test_size=0.2, random_state=42)# Treinando modelo

qtd_dados = len(classes)

#blocos
cv = 5

#dados por bloco
dados_treino = int(qtd_dados*0.7)
dados_teste = int(qtd_dados*0.3)

print('qtd dados total: ', qtd_dados)

print('dados teste: ', dados_teste)

print('dados treino: ', dados_treino)

#importando modelo de classificacao Random Forest    
model  = RandomForestClassifier()

tempo_treino_rf = 0.0
tinicio_rf = time.monotonic()
model.fit(X_train, y_train)
tempo_treino_rf += time.monotonic()-tinicio_rf

tempo_teste_rf = 0.0

###################################
print("\nRandom Forest")

print('Tempo total treino: ', tempo_treino_rf, ' | Tempo total teste: ', tempo_teste_rf)

# file_saida.write('Tempo total treino: ' + str(tempo_treino_rf) + ' | Tempo total teste: ' + str(tempo_teste_rf)+'\n')

tinicio_rf = time.monotonic()
y_pred = model.predict(X_test)
tempo_teste_rf += time.monotonic() - tinicio_rf

#metricas
accuracy = accuracy_score(y_test, y_pred)
ps = precision_score(y_test, y_pred,average='macro')
rs = recall_score(y_test, y_pred,average='macro')
f1s = f1_score(y_test, y_pred,average='macro')
print('Accuracy: %.3f' % accuracy)
print('Precision: %.3f' % ps)
print('Recall: %.3f' % rs)
print('F1 Score: %.3f' % f1s)

# file_saida.write('accuracy: '+ str(accuracy)+'\n')
# file_saida.write('ps: '+ str(ps)+'\n')
# file_saida.write('rs: '+ str(rs)+'\n')
# file_saida.write('f1s: '+ str(f1s)+'\n')

cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                              display_labels=model.classes_)   

disp.plot()
plt.title('matrix rf')
# plt.show()
plt.savefig('15rf.png')


### Extrair a random_forest
import joblib

joblib.dump(model, "./random_forest.joblib", compress=0)

exit(0)
