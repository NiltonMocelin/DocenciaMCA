#concatena csvs, com apenas um descritor

import os

nome_arquivo = 'base-agrupada.csv'

dir_list = os.listdir()

contador_total= 0

file_saida = open(nome_arquivo, 'a+')

for x in dir_list:

    
    if x.endswith(".csv"):

        print(x)

        contador = 0
        file = open(x,'r')

        for l in file:
            if contador == 0:
                if contador_total == 0:
                    contador_total+=1
                    contador+=1
                    file_saida.write(l)
                    continue
                else:
                    contador+=1
                    #nao escrever a primeira linha de todos os arquivos pois eh o descritor
                    continue
            contador+=1
            contador_total+=1
            file_saida.write(l)
        file.close()

file_saida.close()
print("Arquivo escrito: {}, linhas: {}".format(nome_arquivo, contador_total))
