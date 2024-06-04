#concatena csvs, com apenas um descritor

import os

nome_arquivo = 'base-agrupada.csv'

dir_list = os.listdir()

contador_total= 0

file_saida = open(nome_arquivo, 'a+')

linhas_menor_arquivo=9999999999

#contar linhas
for x in dir_list:
    
    if x.endswith(".csv"):
   
        file = open(x,'r')

        linhas_aux = 0

        for l in file:
            linhas_aux+=1

        #excluir a primeira linha == descritor
        linhas_aux-=1

        if linhas_aux < linhas_menor_arquivo:
            linhas_menor_arquivo = linhas_aux

        file.close()

print("Menor arquivo: {}".format(linhas_menor_arquivo))

for x in dir_list:

    if x.endswith(".csv"):

        # print(x)

        contador = 0
        file = open(x,'r')

        for l in file:

            #escrever a mesma qunatidade de linhas de cada arquivo == balancear
            if contador >= linhas_menor_arquivo:
                break

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
        print("escritas {} linhas do arquivo {}".format(linhas_menor_arquivo,x))
        file.close()

file_saida.close()
print("Arquivo escrito: {}, linhas: {}".format(nome_arquivo, contador_total))
