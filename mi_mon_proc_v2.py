import csv
import sys
import json
import codecs
from influxdb import InfluxDBClient

flowsid = 0

def ainflux(flow_list):
	global flowsid
	dic = {}
	json_body =[]	

	json_body.insert(flowsid,{

		"measurement": "Medidas",
		"tags": {
			#"flowid":str(flowsid),
			"6Host":flow_list[4]},
		"fields":{
			"1IP_src":flow_list[0],
			"2IP_dst":flow_list[1],
			"3Port_src":flow_list[2],
			"4Port_dst":flow_list[3],
			#"5Protocol":flow_list[flujo][4],
			"5#Bytes":int(flow_list[5]),
			"7#Paquetes":flow_list[6]}
		})
		#print ("QUIIIITO",json_body.pop(flujo))
	#print(json.dumps(json_body, indent=4,separators=(". ", " = "),sort_keys=True))
	#print("La longitud de json_body es:",len(json_body))
	client.write_points(json_body, protocol='json') # , tags = dic,
	flowsid = flowsid + 1


client = InfluxDBClient(host='localhost', port=8086)

client.drop_database('flows_TFM')
client.create_database('flows_TFM')
client.get_list_database()

client.switch_database('flows_TFM')
cont_g = 0 

flujos = []



with codecs.open('salidamimon.csv','r', encoding='utf-8', errors='replace') as File:    
	reader = csv.reader(File,delimiter=";")
	for row in reader:
		coincidencias = []
		pcks = 0
		#print("")
		#print("")
		#print("")
		#print("La fila a tratar es es:",row)
		#print ("Cont es ---> ",cont)
		#Primer flujo de la captura no puedo comparar con nada
		if cont_g == 0:
			#print("Debes entrar en el primerisimo if")
			row.append(pcks+1)
			flujos.append(row[2:])
			#print("0-MAndo a influx.",flujos)
			ainflux(flujos[0])
			cont_g+=1
		else:
			cont = 0
			for x in range(len(flujos)):
				#print ("COMPARO:",row[2:6],"CON",flujos[x][0:4])
				#print ("cont",cont)
				if row[2:6] == flujos[x][0:4]:
					#print ("Entra en el if")
					coincidencias.append(1)
					cont+=1
				else:
					#print ("Entra en el else")
					coincidencias.append(0)
					cont+=1


			#Poner el host en el flujo bidireccional
			tupla_inversa = []
			#tupla_inversa.append(row[0]) 
			#tupla_inversa.append(row[1])
			tupla_inversa.append(row[3]) 
			tupla_inversa.append(row[2])
			tupla_inversa.append(row[5])
			tupla_inversa.append(row[4])
			#tupla_inversa.append(row[6])
			#print ("TUPLA INVERSA para ponerle host ES ",tupla_inversa)

			# Mirar si lo ultimo que tengo que hacer es escribir en flujos para no duplicar	
			# Veo en que posicion se repite y en funcion de eso sumo 1 paquete y los bytes que correspondan
			try:
				#print("Entras en TRY---")
				indice = coincidencias.index(1)	
				#print("0----------flujos[indice][-2]----------0",flujos[indice][-2])	
				flujos[indice][-1] = flujos[indice][-1]+1
				flujos[indice][-2] = int(flujos[indice][-2])
				flujos[indice][-2] = int(flujos[indice][-2]) + int(row[-1])
				#print ("LLEGA",flujos[indice][-1])
				#print("----VAS DE CAMINO AL IFFFF")
				if row[6] == 'none': # Si me viene con el campo vacío, pero ya sabemos que host se lo ponemos
					#print ("")

					for j in range(len(flujos)):
						#print ("COMPARO:",row[2:6],"CON flujos[j]",flujos[j][0:4])
				
						if row[2:6] == flujos[j][0:4] or tupla_inversa == flujos[j][0:4]:
						
							row[6] = flujos[j][4]
							#print("1-MAndo a influx.",flujos[j])
							ainflux(flujos[j])
							break
	
						else:
							#print ("No existe ninguna entrada con el campo HOST en la tabla")
							pass
				else:
					for j in range(len(flujos)): # Si no viene con campo none, si no con HOST se lo ponemos
	
						if row[2:6] == flujos[j][0:4] or tupla_inversa == flujos[j][0:4]:
							#print ("Entra en el if 3")
							flujos[j][4] = row[6]
							#print("2-MaNDO a influx",flujos[j])
							ainflux(flujos[j])
							break
				
						else:
							#print ("2No existe ninguna entrada con el campo HOST en la tabla")
							pass
			except:
				#print("Entras en EXCEPT---")
				#print ("*********De momento no hay flujos coincidentes.")
				if row[6] == 'none': # Si viene con campo none 

					row.append(pcks+1)
					flujos.append(row[2:]) #Necesario 2 columnas al principio (timestamp y pkt number)
					#print("3-MaNDO a influx",flujos[-1])
					ainflux(flujos[-1])
				else:
					#Hacer esto bien en el caso de que el host no este en la lista de tuplas y no sea none
					row.append(pcks+1)
					flujos.append(row[2:]) 
					#print("4-MaNDO a influx",flujos[-1])
					ainflux(flujos[-1])

			else:
				a = 1
				#print("No ha habido problemas en el try")
	
			#print ("1LAS TUPLAS DE LA FUNCION SON:",flujos)

			#print("TODOS LOS FLUJOS:",flujos)
			pcks = pcks + 1
		#print("ELROWWWW EEES.",row)
		#print ("LAS TUPLAS DE LA FUNCION CON HOST SI LO TIENEN:",flujos)
		#print()
		#print()
		#print()
		#print()
		#print()
		#print()
		#print()


		#ainflux(flujos) #Enviamos solo el ultimo elmento, y por tanto el mas nuevo.. pero si hay actulizaciones?...
print("Numero total de paquetes",pcks)

