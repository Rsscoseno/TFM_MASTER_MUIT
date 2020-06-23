/*
 ****************************************************************************
 * 
 * Ejemplo para compilarlo:
 *   gcc sniffer.c -o sniff -lpcap
 * **************************************************************************
 *
 * Expression			Description
 * ----------			-----------
 * ip				Capture all IP packets.
 * tcp				Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 * port 53			Capture all packets DNS
 * port 443			Capture all packets HTTPS
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"TFM Monitorizador en SDN -> sniffer"
#define APP_DESC		"Sniffer usando libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"Basado en el material de https://www.tcpdump.org/pcap.html"

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/* Puerto para la conexion con el controlador*/
#define PORT1 9001
#define IP_IX "192.168.157.132"//"127.0.0.1"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* Cabecera ethernet 14 bytes */
#define SIZE_ETHERNET 14

/* Direccion ethernet 6 bytes */
#define ETHER_ADDR_LEN	6

/* Cabecera UDP*/
#define SIZE_UDP        8               	

/* Cabecera Ethernet */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* direccion host destino */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* direccion host origen */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* Cabecera IP */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | Longitud cabecera >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* Longitud total */
        u_short ip_id;                  /* id */
        u_short ip_off;                 /* offset */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocolo */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest direccion */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Cabecera TCP */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* puerto origen */
        u_short th_dport;               /* puerto destino */
        tcp_seq th_seq;                 /* numero seq */
        tcp_seq th_ack;                 /* numero ack */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* Cabecera UDP. */
struct sniff_udp {
        u_short uh_sport;               /* puerto origen */
        u_short uh_dport;               /* puerto destino */
        u_short uh_ulen;                /* Longitud UDP */
        u_short uh_sum;                 /* udp checksum */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);


/*
 * Imprimir los datos iniciales de la aplicacion
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * Texto de ayuda
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
//****************************************************************************************************
#define DNS_BYTE_POINTER 0xC0
#define DNS_OFFSET_MASK 0x3FFF
#define DNS_NAME_END 0x00
#define LABEL_SEP "."
#define GET_DNS_OFFSET(in) (ntohs((*(uint16_t*)in))&DNS_OFFSET_MASK)

#define CNAME_TYPE 5
#define A_TYPE 1
#define AAAA_TYPE 28 

 /**
 * Función main que se encarga de leer un nombre en formato DNS
(incluyendo punteros) y lo copia (en texto) a la variable output
 * @param input
 * Puntero al inicio del nombre DNS a leer
 * @param start
 * Puntero al inicio del paquete DNS. Se usa cuando hay punteros para
moverse al offset que se indique
 * @param output
 * Cadena de salida con el nombre de dominio reconstruido
 * @return
 *   La función devuelve -1 si hay algún error y la longitud (en bytes)
que hay que saltar para llegar al siguiente campo DNS. El valor
devuelto NO es la longitud del nombre de dominio reconstruído
 */

struct Tupla{
	char outputDNS[40];
	char ip_dns[15];
};

struct Tupla readDNSName(uint8_t *input,uint8_t *start, int size_payload)//,char *output_ip)
{
        int outlen=0;
        int len=-1;
        uint8_t *in_aux;

	in_aux = input;

	struct Tupla var;
	int contador = 0;
	
	int lenInput = strlen(in_aux);
	int lenStart = strlen(start);

	char mid[64] ="";
	//char host[10];

	//printf("\n-> Inaux: %d \n",*in_aux);

        while(*in_aux!=DNS_NAME_END)//Bucle para obtener el nombre
        {
		
                if(*in_aux>=DNS_BYTE_POINTER)
                {
      			printf("\nEntra en el IFFF\n");
                        uint16_t offset=GET_DNS_OFFSET(in_aux);
			printf("OFFSET: %d", offset);
                         if (len < 0)
                                len = in_aux - input + 1;
                        in_aux=start+offset;
			//contador = start+offset;               
                }
                else
                {	
                        uint8_t label_len=*in_aux;
                        
			in_aux++;
			contador++;
			//printf("\n label_len es : %d \n",label_len);
			int lenHost = label_len; // +1 para poder poner el punto
			char host[lenHost];
			int j;
			int k;
			for(j=0;j<label_len;j++){
				if (isprint(*in_aux)!=0)
					host[j] = *in_aux;
				//printf("\nhost[%d] %c\n",j,host[j]);
				in_aux++;
				contador++;
			}
			
			strcat(host,"."); //Añado el punto de separador del nombre DNS	
			//printf("\n\n2 El valor de HOST todo junto es %s",host);
			for(k=0;k<=j;k++){
				if (isprint(host[k])!=0)
					host[k] = host[k];
				//printf("\nhost[%d] %c\n",k,host[k]);

			}
			//printf("\n\n3 El valor de HOST todo junto despues de la comprobacion de los caracteres es %s",host);
			//printf("\n---->strlen(HOST) ES: %d\n",strlen(host));
		
			strcat(mid,host);
                        
			memset(host,0,strlen(host));
			//printf("\n\n3 El valor de HOST despues de cada iteracion es: %s",host);
			outlen+=label_len;
                }
               
        }  

	//printf("\n---->MID ES: %s\n",mid);
	int lenDNS = strlen(mid);
	//printf("\n---->LENDNS ES: %d\n",lenDNS);
	//var.outputDNS = malloc(lenDNS+1); //char *outputDNS = malloc(lenDNS+1);
	var.outputDNS[lenDNS+1];
	memcpy(var.outputDNS,mid,lenDNS+1);
	//printf("\n\n PASA EL MALLOC \n\n");	

	var.outputDNS[lenDNS-1]='\0';

	printf("\noutputDNS es:%s\n",var.outputDNS);
	//return outputDNS;
	

//*--------------------- PARA OTRA FUNCION-------------------------------------*
	//in_aux apunta al final del bucle a 00 de despues del host     
	in_aux++;contador++;
	in_aux++;contador++;
	// Estoy en Type y quiero que sea A es decir 0x01
	in_aux++;contador++;
	in_aux++;contador++;
	// Ahora estoy en en class que debe ser 0x01	
	in_aux++; // Apunto al dato inmediato de 0x01

	//char ip_dns[10]="";
	strcpy(var.ip_dns,"");
	//type A -> 1 a host address
	///*Bucle para obtener el type - Interesa type A*/
	*in_aux++;contador++;
	*in_aux++;contador++;
	// Apunta CNAME del primer answer
	while(contador < size_payload){ //'\0'(uint8_t) 238 *in_aux!= (uint8_t) 192
		//printf("\n LLEGAS AL WHILE valor ina_aux %02x\n \n",*in_aux);
		if (*in_aux == (uint8_t)1){
			//printf("\n LLEGAS AL PRIMER IF DEL WHILE \n");
			*in_aux++;contador++;
			*in_aux++;contador++;
			if (*in_aux == (uint8_t)1){
				//printf("\n-> Inaux: %02x\n",*in_aux);
				// Paso el campo TTL
				*in_aux++;contador++;
				*in_aux++;contador++;
				*in_aux++;contador++;
				*in_aux++;contador++;
				// Paso el campo data length (que sera 4(IP))
				*in_aux++;contador++;
				*in_aux++;contador++;
				*in_aux++;contador++;
				//printf("\n-> Me apuntas al principio de la IP?: %02x\n",*in_aux);		
				
				int pos_ip = 0;
				//strcpy(var.ip_dns,"");
				for(int counter = 0; counter<4;counter++){ //!= 0xC0					
					//printf("\n\n Primer octeto IP %d", (int)*in_aux);				
					char octeto[3];
											
					sprintf(octeto, "%d",*in_aux);
					//printf("\n\n OCTETO DICE SER:%s",octeto);					

					strcat(var.ip_dns,octeto);
					if(counter!=3)// Para poner unicamente 3 puntos según el formato IP
						strcat(var.ip_dns,".");

					*in_aux++;contador++;

				}
				break;
			}else
				*in_aux++;contador++;
		//}else if (*in_aux == (uint8_t)5){
			
		//	continue;
		}else
			*in_aux++;contador++;

	}
	printf("\n \n\n\nLA IP A LA QUE CONECTA ES:%s",var.ip_dns);
	//return outputDNS;
	return var;

}
//****************************************************************************************************


/*FUNCION PARA OBTENER SI ES UNA DNS ANSWER VALIDA*/
int answDNS(char *payload,int lenPayload){
	u_char *ch;
	int sup = 7;
	int bin[7];
	ch = payload;
	int array[lenPayload];

	for(int i = 0; i < lenPayload; i++) {
		array[i] = *ch;
		//printf("%d[%d]",array[i],i);
		ch++;
	}

	// TRANSFORMO EN BINARIO PARA COMPROBAR SI ES UNA ANSWER
	while(sup >= 0)
	{
		if(array[2] & (((long int)1) << sup)){
			bin[sup] = 1;
		}
		else{
			bin[sup] = 0;
		}
		sup--;
	}

	//Diferenciar entre Query DNS y answer DNS
	if(bin[7]>=1 && array[2]==129 && array[3]==128){
		return 1;
	}else
		return -1;
	
}

#define SALTO 0x0d
/*FUNCION PARA OBTENER EL HOST EN HTTP*/
char* getHostHTTP(char *payload,int lenPayload){

	char word1[] = "Host:";
	char word2[] = "User";
	
	char *ret1=NULL;
	char *ret2=NULL;
	
	int len1=0;
	int len2=0;
	int lenHost=0;
	int j;
	char *control = malloc(2 * sizeof(char));		


	char host[6];

	ret1 = strstr(payload,word1);
	ret2 = strstr(payload,word2);
	
	//Si existe la palabra HOST en el payload
	if (ret1 != NULL){

		len1 = strlen(ret1);
		//printf("LEN1:%d\n",len1);
		len2 = strlen(ret2);
		//printf("LEN2:%d\n",len2);
		lenHost = len1-len2-2-6;
		
		char pag[lenHost];
		char *outputHTTP = malloc(lenHost+1);
				
		//printf("\nlenHost es:%d\n",lenHost);
		sscanf(ret1,"%s %s",host,pag);
		//printf("El HOST es: %s\n",pag);
		
		for(j=0;j<lenHost;j++){
			outputHTTP[j] = pag[j];
		}
		outputHTTP[lenHost]='\0';

		//printf("\nOUTPUTHTTP es:%s\n",outputHTTP);
		return outputHTTP;
	}else{ //Si no existe la palabra HOST en el payload
		control[0] = '1';
		control[1] = '\0';	
		//printf("\n\n CONTROL ES:%s\n",control);
		return control;
	}
}

// PARTE DE HTTPS  
#define TLS_HANDSHAKE 22
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_NAME 0x0000
#define TLS_HOST_NAME 0
#define TLS_TIME_LEN 4
#define TLS_RANDOM_BYTES_LEN 28
#define TLS_MIN_HLEN 42
/**Macro para el número de puerto HTTPS*/
#define HTTPS_PORT 443


/*static inline uint32_t bswap24(uint32_t data) {

       
        uint8_t *d= (uint8_t*)&data;
        uint8_t temp=d[0];
        d[0]=d[2];
        d[2]=temp;
       
        return data;
}*/
//#ifdef DP_SSL
char *getHostHTTPS(uint8_t *data,int size) // Antiguo:uint8_t *data,uint16_t size
{
	

	printf("\n\n\nLlegas al getHostHTTPs\n\n");
	
	//printf("\n\n****-----****-----****\n %s\n\n-----------********-------**\n\n\n",data);
	
	char paginaHTTPS[40];
	char *outputHTTPS;
        int n=0;
        //uint16_t len=0;

       	printf("\n\n\nPAsas la inicializacion de la variable\n\n");
        if(data[n]!=TLS_HANDSHAKE)
                return "1";
        n+=(sizeof(uint8_t)+sizeof(uint32_t));
        //len= ntohs(*((uint16_t*)(&data[n])));
        //n+=sizeof(uint16_t);
        if(data[n]!=TLS_CLIENT_HELLO)
                return "1";

        //n+=sizeof(uint8_t);
	//printf("\n\n\nPasas la comprobacion de clientHello %d\n\n",&data);

        //uint32_t lengthHello=0;
        //memcpy(&lengthHello,&data[n],3*sizeof(uint8_t));
        //lengthHello=bswap24(lengthHello);


        //n+=(5*sizeof(uint8_t))+TLS_TIME_LEN+TLS_RANDOM_BYTES_LEN;
        n+=(6*sizeof(uint8_t))+TLS_TIME_LEN+TLS_RANDOM_BYTES_LEN;

        uint8_t sessionIdLen=data[n];
        n+=sessionIdLen+sizeof(uint8_t);

        uint16_t cipherLen= ntohs(*((uint16_t*)(&data[n])));
        n+=cipherLen+sizeof(uint16_t);


        uint8_t compressionLen=data[n];
        n+=compressionLen+sizeof(uint8_t);
       
        uint16_t extensionsLen=ntohs(*((uint16_t*)(&data[n])));
        n+=sizeof(uint16_t);
	
	printf("\n\n\n EXTENSIONLEN %d\n\n",extensionsLen);
       
        int i=0;
        while(i<extensionsLen){
		//printf("\n\n\nEntras en el while %d \n\n",i);
                uint16_t extensionType=ntohs(*((uint16_t*)(&data[n])));
                n+=sizeof(uint16_t);
       
                uint16_t extensionLen=ntohs(*((uint16_t*)(&data[n])));
                n+=sizeof(uint16_t);
                //printf("Extension Type:%x Len:%d\n",extensionType,extensionLen);
                if(extensionType==TLS_SERVER_NAME)
                {
		printf("\n\n\nEntras en TLS_SERVER_NAME \n\n");
                        uint16_t listLen=ntohs(*((uint16_t*)(&data[n])));
                        printf("List len %d\n",listLen);
                        n+=sizeof(uint16_t);
                        if((listLen>0)&&(data[n]==TLS_HOST_NAME))
                        {
                                n+=sizeof(uint8_t);
                                uint16_t nameLen=ntohs(*((uint16_t*)(&data[n])));
				printf("Name Len %d\n",nameLen);
                                n+=sizeof(uint16_t);
                                printf("n:%d %d\n",n,i);
                                //printf("Copiando..%d\n",MIN(nameLen,CERTNAME_LEN));
                                            
				memcpy(paginaHTTPS,&data[n],nameLen); //MIN(nameLen,CERTNAME_LEN)
                                paginaHTTPS[nameLen] = 0x00; /*Fin de cadena*/ //MIN(nameLen,CERTNAME_LEN)
                                outputHTTPS = paginaHTTPS;
                       		printf("\n\n **/*/*/*/*/*/*/OUTPUT en HTTPS es:%s\n",outputHTTPS);
                                return outputHTTPS;               
                        }
               
                }
                n+=extensionLen;
                i+=extensionLen+sizeof(uint32_t);
        }
	
        return '\0';
}


/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


void EnvioquintuplaTCPconTAG(long long int t_us,const struct sniff_ip *ipS, const struct sniff_tcp *pS,char *protocol,char*tag, int bytes){

printf("\n\n****TAG NADA MAS LLEGAR A LA FU¿ANSION: %s",tag);


	char paginahttps[30];
	
	memcpy(paginahttps,tag,30);
//ENVIO DE DATOS AL CONTROLADOR

	//SOCKET 1 -> Mando el numero de paquetes que voy a enviar
	//struct sockaddr_in address;
	//int sock = 0, valread;
	//struct sockaddr_in serv_addr;

	//if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){ // TCP ---> if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
	//	printf("\n Socket creation error \n");
	//	return;
	//}


	//memset(&serv_addr, '0', sizeof(serv_addr));

	//serv_addr.sin_family = AF_INET;
	//serv_addr.sin_port = htons(PORT1); //PORT1

	// Convert IPv4 and IPv6 addresses from text to binary form
	//if(inet_pton(AF_INET, IP_IX, &serv_addr.sin_addr)<=0) { // 192.168.12.134
	//	printf("\nInvalid address/ Address not supported \n");
	//	return;
	//}

	//if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
	//	printf("\nConnection Failed \n");
	//	return;
	//}




	char ip_Origen[INET_ADDRSTRLEN];
	char ip_Destino[INET_ADDRSTRLEN];
	printf("\n\n****TAG ANTES DE INET %s",paginahttps);
	inet_ntop(AF_INET, &ipS->ip_src, ip_Origen, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ipS->ip_dst, ip_Destino, INET_ADDRSTRLEN);
	printf("\n\n****TAG DESPUES DE INET %s",paginahttps);
	int PortorInt =  ntohs(pS->th_sport);
	int PortDestInt = ntohs(pS->th_dport);
	char Portor[15];
	char PortDest[15];
	char byts[15];

	sprintf(Portor, "%d", PortorInt);
	sprintf(PortDest, "%d", PortDestInt);
	sprintf(byts, "%d", bytes);

	
	
/*

	char *array0 = ip_Origen;
	char *array1 = ip_Destino;
	char *array2 = Portor;
	char *array3 = PortDest;
	char *array4 = protocol;
	char *array5 = tag;
	char *array6 = byts;

*/
	char *array0 ="";
	char *array1 ="";
	char *array2 ="";
	char *array3 ="";
	char *array4 ="";
	char *array5 ="";
	char *array6 ="";

	array0 = ip_Origen;
	array1 = ip_Destino;
	array2 = Portor;
	array3 = PortDest;
	array4 = protocol;
	array5 = tag;
	array6 = byts;

	printf("\n\n*\n*\n\n");
	printf("\n\n****Envio al controlador el host %s",tag);
	//printf("\n\n\n\n\n");
	
	
	FILE *f=fopen("salidamimon.csv","a");
	if(f==NULL) return;
		fprintf(f,"%s,%s,%s,%s,%s,%s,%s\n",array0, array1, array2, array3, array4, array5, array6);
	fclose(f);
	return;


}

void EnvioquintuplaUDPconIPTAG(long long int t_us,const struct sniff_ip *ipS, char* ip_dns, const struct sniff_udp *pS,char *protocol,char*tag, int bytes)
{

//ENVIO DE DATOS AL CONTROLADOR

/*	//SOCKET 1 -> Mando el numero de paquetes que voy a enviar
	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){ // TCP ---> if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error \n");
		return;
	}


	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT1); //PORT1

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, IP_IX, &serv_addr.sin_addr)<=0) { // 192.168.12.134
		printf("\nInvalid address/ Address not supported \n");
		return;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		printf("\nConnection Failed \n");
		return;
	}
*/
	char ip_Origen[INET_ADDRSTRLEN];
	char ip_Destino[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ipS->ip_src, ip_Origen, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ipS->ip_dst, ip_Destino, INET_ADDRSTRLEN);

	int PortorInt =  ntohs(pS->uh_sport);
	int PortDestInt = ntohs(pS->uh_dport);
	char ipdns[15];
	char Portor[5];
	char PortDest[5];
	char byts[5];

	sprintf(Portor, "%d", PortorInt);
	sprintf(PortDest, "%d", PortDestInt);
	sprintf(byts, "%d", bytes);

	//itoa(ntohs(pS->th_sport), Portor, 10);

	//printf("PUERTO ORIGEN: %s\n", Portor);
	//printf("PUERTO DESTINO: %s\n", PortDest);


	//char quintuplaConTag[120]="";	
	if(*ip_dns == '\0'){
		char *array0 = ip_Origen;
		char *array1 = ip_Destino;
		char *array2 = Portor;
		char *array3 = PortDest;
		char *array4 = protocol;
		char *array5 = tag;
		char *array6 = byts;
		char *array7 = ipdns;

		/*strcat(quintuplaConTag,array0);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array1);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array2);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array3);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array4);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array5);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array6);

		sendto(sock, quintuplaConTag,strlen(quintuplaConTag),0,(struct sockaddr *)&serv_addr,sizeof(serv_addr));//TCP ---> write(sock, cadena,strlen(cadena));*/

		FILE *f=fopen("salidamimon.csv","a");
		if(f==NULL) return;
		fprintf(f,"%s,%s,%s,%s,%s,%s,%s\n",array0, array1, array2, array3, array4, array5, array6);
		fclose(f);
		return;
	}else{
		char *array0 = ip_dns;
		char *array1 = ip_Destino;
		char *array2 = Portor;
		char *array3 = PortDest;
		char *array4 = protocol;
		char *array5 = tag;
		char *array6 = byts;

		/*strcat(quintuplaConTag,array0);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array1);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array2);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array3);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array4);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array5);
		strcat(quintuplaConTag,",");
		strcat(quintuplaConTag,array6);

		sendto(sock, quintuplaConTag,strlen(quintuplaConTag),0,(struct sockaddr *)&serv_addr,sizeof(serv_addr));//TCP ---> write(sock, cadena,strlen(cadena));*/
		FILE *f=fopen("salidamimon.csv","a");
		if(f==NULL) return;
		fprintf(f,"%s,%s,%s,%s,%s,%s,%s\n",array0, array1, array2, array3, array4, array5, array6);
		fclose(f);
		return;
	}


	

	return;
	//close(sock);

}

void EnvioquintuplaUDPconTAG(long long int t_us,const struct sniff_ip *ipS, const struct sniff_udp *pS,char *protocol,char*tag, int bytes){


//ENVIO DE DATOS AL CONTROLADOR

	//SOCKET 1 -> Mando el numero de paquetes que voy a enviar
	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){ // TCP ---> if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error \n");
		return;
	}


	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT1); //PORT1

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, IP_IX, &serv_addr.sin_addr)<=0) { // 192.168.12.134
		printf("\nInvalid address/ Address not supported \n");
		return;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		printf("\nConnection Failed \n");
		return;
	}

	char ip_Origen[INET_ADDRSTRLEN];
	char ip_Destino[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ipS->ip_src, ip_Origen, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ipS->ip_dst, ip_Destino, INET_ADDRSTRLEN);

	int PortorInt =  ntohs(pS->uh_sport);
	int PortDestInt = ntohs(pS->uh_dport);
	char Portor[5];
	char PortDest[5];
	char byts[5];

	sprintf(Portor, "%d", PortorInt);
	sprintf(PortDest, "%d", PortDestInt);
	sprintf(byts, "%d", bytes);

	//itoa(ntohs(pS->th_sport), Portor, 10);

	//printf("PUERTO ORIGEN: %s\n", Portor);
	//printf("PUERTO DESTINO: %s\n", PortDest);


	char quintuplaConTag[120]="";	
	
	char *array0 = ip_Origen;
	char *array1 = ip_Destino;
	char *array2 = Portor;
	char *array3 = PortDest;
	char *array4 = protocol;
	char *array5 = tag;
	char *array6 = byts;
	
	strcat(quintuplaConTag,array0);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array1);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array2);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array3);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array4);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array5);
	strcat(quintuplaConTag,",");
	strcat(quintuplaConTag,array6);

	sendto(sock, quintuplaConTag,strlen(quintuplaConTag),0,(struct sockaddr *)&serv_addr,sizeof(serv_addr));//TCP ---> write(sock, cadena,strlen(cadena));
	
	close(sock);

}



long long int time_stamp(){


	/* Example of timestamp in microsecond. */
	struct timeval timer_usec; 
	long long int timestamp_usec; /* timestamp in microsecond */
	if (!gettimeofday(&timer_usec, NULL)) {
		timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll + (long long int) timer_usec.tv_usec;
	}
	else {
		timestamp_usec = -1;
	}

	
	return timestamp_usec;

}


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp; 		/* The UDP header */
	char *payload;                   	/* Packet payload */
	
	u_int64_t time;

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	char *ipOr;
	char *ipDest; 

	int resultado = 1;

	/*UDP*/
    	int i;
	u_char *ch;
	int answ;

	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	// TIME STAMP
	long long int tiempo = time_stamp();
	//printf("  Timestamp: %lld\n",tiempo);
	/* IP origen y destino */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			/* define/compute tcp header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
			}
	
			//printf("   Src port: %d\n", ntohs(tcp->th_sport));
			//printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			//printf("   Payload (%d bytes):\n", size_payload);
			/*
			 * Print payload data; it might be binary, so don't just
			 * treat it as a string.
			 */

			if (ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80){
				char *outputHTTP = "";
				if (size_payload > 0) {
					//printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					outputHTTP = getHostHTTP(payload,size_payload);//,outputHTTP);
					if(*outputHTTP != '\0' && *outputHTTP!='1'){
						//printf("La pagina es: %s",outputHTTP);
						//Cada paquete debo enviarlo al colector python para ir representando las estadisticas
						EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTP",outputHTTP,size_payload);
			
					}else{
						//printf("No hay campo Host");
						//Cada paquete debo enviarlo al colector python
						//EnvioquintuplaTCP(tiempo,ip,tcp,"HTTP",size_payload);
						EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTP","none",size_payload);
						}
				}
				else{
					//Todos los paquetes
					//EnvioquintuplaTCP(tiempo,ip,tcp,"HTTP",size_payload);
					EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTP","none",size_payload);
				}
			}else if(ntohs(tcp->th_sport) == 443 || ntohs(tcp->th_dport) == 443){
				char *outputHTTPS="";//'\0';
				printf("\n\n Llegas a la parte del puerto 443\n\n");
				if (size_payload > 0){
					printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					//uint8_t* data_uint = (uint8_t*)atoi(payload);
					outputHTTPS = getHostHTTPS(payload,size_payload);//,outputHTTP); //
					if(*outputHTTPS != '\0' && *outputHTTPS!='1'){
						printf("---->La pagina es: %s\n",outputHTTPS);			
						EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTPS",outputHTTPS,size_payload);
					}else{
						printf("No hay campo Host");
						EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTPs","none",size_payload);
					}
				}/*else if(size_payload > 1400){
					//Todos los paquetes
					printf("\nNo hay payload valido");
					//EnvioquintuplaTCP(tiempo,ip,tcp,"HTTP",size_payload);
					EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTPs","none",size_payload);
				}*/else{
					//Todos los paquetes
					printf("\nNo hay payload valido");
					//EnvioquintuplaTCP(tiempo,ip,tcp,"HTTP",size_payload);
					EnvioquintuplaTCPconTAG(tiempo,ip,tcp,"HTTPs","none",size_payload);
				}
				
			}else{
				printf("\n\n Llegas al else de la parte de que los puertos no son ni 443 ni 80\n\n");
				return;
			}
			//free;
			return;

		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			/* define/compute udp header offset */
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);

			printf("   Src port: %d\n", ntohs(udp->uh_sport));
			printf("   Dst port: %d\n", ntohs(udp->uh_dport));

			//size_udp = ntohs(udp->uh_ulen);

			/* define/compute udp payload (datagram) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
	
			/* compute udp payload (datagram) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
			if (size_payload > ntohs(udp->uh_ulen))
                		size_payload = ntohs(udp->uh_ulen);

			char *host_DNS = "";	
			struct Tupla t;
			strcpy(t.ip_dns,"");
			if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				// PARA IMPRIMIR SOLO LO RELEVANTE
				//print_payload(payload, size_payload);
				ch = payload + 12;
				answ = answDNS(payload,size_payload);
				if(answ == 1){
					printf("\n\n ES UNA ANSWER DNS VALIDA, ME VALE \n\n");
					
					//for(int pos = 0; pos < size_payload; pos++) {
						//if (pos==inicio){
							//host_DNS = readDNSName(ch,payload);//,&ip_DNS);
							struct Tupla t = readDNSName(ch,payload,size_payload);

							printf("\nLA IP EN EL MAIN ES:%s\n",t.ip_dns);//ip_DNS);
							if (t.outputDNS != '\0' && t.ip_dns != ""){ //habia " " *host_DNS
								EnvioquintuplaUDPconIPTAG(tiempo,ip,t.ip_dns,udp,"DNS",t.outputDNS,size_payload);
								printf("LA PAGINA ES: %s \n",t.outputDNS);//host_DNS);
								ch++;
								break;
							}else if(t.outputDNS != '\0' && t.ip_dns == ""){
								//EnvioquintuplaUDPconTAG(tiempo,ip,udp,"DNS",t.outputDNS,size_payload);
								EnvioquintuplaUDPconIPTAG(tiempo,ip,t.ip_dns,udp,"DNS",t.outputDNS,size_payload);
								break;
							}else{
								//EnvioquintuplaUDPconTAG(tiempo,ip,udp,"DNS","none",size_payload);
								EnvioquintuplaUDPconIPTAG(tiempo,ip,t.ip_dns,udp,"DNS",t.outputDNS,size_payload);
								break;
							}
					
				}else{
					printf("\nNO ES UN ANSWER DNS VALIDA o es una query\n");

					EnvioquintuplaUDPconTAG(tiempo,ip,udp,"DNS","none",size_payload);
				}
					
				printf("\n");
		
			}
			free;
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	

return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] ip-> all  (port 443) port 80*/
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = atoi(argv[1]); //-1;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 1) {
		printf( "Error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		

	}
	/* find a capture device if not specified on command-line */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	

return 0;
}


