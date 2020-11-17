/*************************************************************************** 
 
      - jjramos, diciembre de 2004 
      - "Completo" programa de ejemplo de uso de libpcap y análisis de las 
cabeceras IP. 
      - Compilación: gcc analizador.cc -o analizador -lpcap 
 
****************************************************************************/ 
 
#include <stdio.h> 
#include <pcap.h> 
#include <string.h> 
#include <netinet/in.h> 
#include <netdb.h> 
 
#define ETHERTYPE_IP 0x0800 
 
#define LINE_LEN 16 
 
#define TIPO_EN_VIVO 1 
#define TIPO_EN_FICHERO 2 
 
typedef struct { 
  unsigned char byte1; 
  unsigned char byte2; 
  unsigned char byte3; 
  unsigned char byte4;  
} tdireccion_ip; 

typedef struct { 
  unsigned char version_longcabecera; /* 4 bits versio'n, 4 bits longitud de 
cabecera */ 
  unsigned char tos; /* Tipo de servicio */ 
  unsigned short longitud; /* longitud total del datagrama */ 
  unsigned short id; /* Identificacio'n */ 
  unsigned short indicadores_despfragmento; /* 3 bits de indicadores, 13 bits de 
fragmento */ 
  unsigned char ttl; /* Tiempo de vida */ 
  unsigned char protocolo; /* protocolo */ 
  unsigned short suma; /* Suma de comprobacio'n (checksum) de la cabecera */ 
  tdireccion_ip dir_origen; /* direccio'n IP del origen */ 
  tdireccion_ip dir_destino; /* direccio'n IP del destino */ 
  unsigned int opciones_relleno; /* 24 bits opciones y 8 de relleno */ 
 
  unsigned char *datos; 
} tdatagrama_ip; 
 
typedef struct{ 
  unsigned  char direccion_origen[6]; 
  unsigned char direccion_destino[6]; 
  unsigned short tipo; 
} ttrama_ethernet; 
 
ip_mostrar(tdatagrama_ip datagrama) 
{ 
  int i; 
  char buffer[256]; 
 
  struct protoent *es_protocolo; 
   
  printf(" 0                   1                   2                   3\n"); 
  printf(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n"); 
  printf("+-Ver---+-HL----+-TOS-----------+-Longitud----------------------+\n"); 
  /* versio'n, IHL, tos, longitud */ 
  printf("| %-6d| 4x%-4d| 0x%-12x| %-30d|\n", 
       (datagrama.version_longcabecera&0xF0)>>4, 
       (datagrama.version_longcabecera&0x0F), 
       datagrama.tos, 
       ntohs(datagrama.longitud)); 
 
  printf("+-Id----------------------------+-Indi--+-Desp. del fragmento---+\n"); 
 
  printf("| %-30d| 0x%-4x| %-22d|\n", 
       ntohs(datagrama.id),  
       (ntohs(datagrama.indicadores_despfragmento)&0xE000)>>13,  
       (ntohs(datagrama.indicadores_despfragmento)&0x1FFF)); 
  printf("+-TTL-----------+-Protocolo-----+-Suma de comprobacio'n---------+\n"); 
 
 
  es_protocolo=getprotobynumber(datagrama.protocolo); 
 
  if(es_protocolo!=0){ 
    sprintf(buffer,"%s",es_protocolo->p_name); 
  } else { 
    sprintf(buffer,"0x%x",datagrama.protocolo); 
  } 
 
  printf("| %-14d| %-14s| 0x%-28x|\n", 
       datagrama.ttl,   
       buffer, 
       ntohs(datagrama.suma)); 
  printf("+-Direccio'n IP origen------------------------------------------+\n"); 
  printf("|                       %3d.%3d.%3d.%3d                         |\n", 
       datagrama.dir_origen.byte1, 
       datagrama.dir_origen.byte2, 
       datagrama.dir_origen.byte3, 
       datagrama.dir_origen.byte4); 
 
  printf("+-Direccio'n IP destino-----------------------------------------+\n"); 
  printf("|                       %3d.%3d.%3d.%3d                         |\n", 
       datagrama.dir_destino.byte1, 
       datagrama.dir_destino.byte2, 
       datagrama.dir_destino.byte3, 
       datagrama.dir_destino.byte4); 
  printf("+-Opciones--------------------------------------+----Relleno----+\n"); 
 
  printf("| 0x%-44x| %-14d|\n", 
       (ntohs(datagrama.opciones_relleno)&0xFFFFFF00)>>8, 
       (ntohs(datagrama.opciones_relleno)&0x000000FF)); 
  printf("+---------------------------------------------------------------+\n");
        
 
  return 0; 
} 
 
 
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *); 
 
int mostrar_interfaces_disponibles(void){ 
  int n_interfaces=0; 
  pcap_if_t *alldevs; 
  pcap_if_t *d; 
  int i=0; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
 
  printf(" Dispositivos disponibles:\n\n"); 
 
  /* Obtiene la lista de dispositivos: */ 
  /* ***Usar*** pcap_findalldevs(&alldevs, errbuf) */ 
     
  /* Print the list */ 
  for(d=alldevs;d;d=d->next) 
    { 
      printf("\t- [%s]", d->name); 
      if (d->description) 
      printf(" (%s)\n", d->description); 
      else             
      printf(" (No hay descripción disponible)\n"); 
    } 
     
  if(i==0) 
    { 
      printf("\nNo se encontraron dispositivos válidos.\n"); 
      return; 
    } 
 
  /* We don't need any more the device list. Free it */ 
  /* ***Usar***  pcap_freealldevs */ 
 
  return n_interfaces;  
 
} 
 
 
main(int argc, char **argv) { 
 
  struct bpf_program filtro; 
  bpf_u_int32 mascara_red, direccion_red; 
  pcap_t *fp; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  int tipo=-1; 
 
  if(argc < 2){ 
 
    fprintf(stderr,"Sintaxis:\n\t%s -i <interfaz de red> [filtro]\n\t%s -f 
<fichero de volcado> [filtro]\n\t%s -l", argv[0],argv[0],argv[0]); 
    return -1; 
 
  } 
 
  switch(argv[1][1]){ 
  case 'i': 
           
    if(argc<3) 
      return 1; 
 
    tipo=TIPO_EN_VIVO; 
    /* ***Usar*** pcap_open_live */ 
    
    break; 
 
  case 'f': 
 
    if(argc<3) 
      return 1; 
 
    tipo=TIPO_EN_FICHERO; 
    /* Apertura del fichero de captura */ 
    /* ***Usar***  pcap_open_offline */ 
 
    break; 
 
  case 'l': 
        
    return mostrar_interfaces_disponibles(); 
    break; 
 
  default: 
    fprintf(stderr,"Error: opción -%c no válida.\n",argv[1][1]); 
    return 1; 
    break; 
  } 
 
  /* En caso de que se haya especificado un filtro: */ 
  if(argc>3){ 
    /* Obtenemos cuál es la máscara de red asociada al dispositivo abierto: */ 
    /* ***Usar*** pcap_lookupnet */ 
 
    /* Compilamos la expresión en "filtro": */ 
    /* ***Usar*** pcap_compile */ 
     
    /* Establecemos un filtro para el tráfico: */  
 
    /* ***USar pcap_setfilter *** */ 
     
    printf("Asignado filtro \"%s\"\n",argv[3]); 
  } 
 
  /* Lee y procesa tramas hasta que se llegue a EOF. */ 
  /* ***Usar*** pcap_loop; */
 
  return 0; 
} 
 
 
void dispatcher_handler(u_char *temp1,  
                        const struct pcap_pkthdr *header, const u_char 
*pkt_data) 
{ 
  u_int i=0; 
         
  tdatagrama_ip *datagrama; 
  ttrama_ethernet *trama; 
 
  /* print pkt timestamp and pkt len */ 
  printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
 
  /* Comprobamos que sea un datagrama IP */ 
 
  trama=(ttrama_ethernet *)(pkt_data); 
 
  if(ntohs(trama->tipo)== ETHERTYPE_IP){ 
     
    datagrama=(tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet)); 
    ip_mostrar(*datagrama); 
  } 
   
  printf("\n\n");      
     
} 
 