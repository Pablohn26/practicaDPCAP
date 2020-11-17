/* Pablo was here otra vez
 * Diego was here
 * File:   main.c
 * Author: diegol
 *
 * Created on 22 de noviembre de 2011, 11:25
 */

/*************************************************************************** 
 
      - jjramos, diciembre de 2004 
      - "Completo" programa de ejemplo de uso de libpcap y análisis de las 
cabeceras IP. 
      - Compilación: gcc analizador.cc -o analizador -lpcap 
 
****************************************************************************/ 
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h> 
#include <pcap.h> 
#include <string.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <unistd.h>//Para el sleep

#define ETHERTYPE_IP 0x0800 
#define ACK 0x0010
#define SYN 0x0002
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
    unsigned short sourceport;
    unsigned short destport;
    unsigned short longitud;
    unsigned short checksum;
    unsigned char* datos;
} tdatagrama_udp;

typedef struct {
    unsigned short sourceport;
    unsigned short destport;
    int numsecuencia;
    int ack;
    unsigned short offset_reserved_y_flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short pointer;
    int options_y_padding;
    unsigned char* datos;    
} tdatagrama_tcp;

typedef struct{
    unsigned char tipo;
    unsigned char codigo;
    unsigned short checksum;
    unsigned short identificador;
    unsigned short num_secuencia;
    unsigned char* datos;
} tdatagrama_icmp;

typedef struct {
    tdireccion_ip iporig, ipdest;
    unsigned short porig,pdest;
    int paso;
    unsigned long int carga;
} cuadrupla;

cuadrupla c [15];
int utiles = 0;

typedef struct { 
  unsigned char version_longcabecera; /* 4 bits versio'n, 4 bits longitud de cabecera */ 
  unsigned char tos; /* Tipo de servicio */ 
  unsigned short longitud; /* longitud total del datagrama */ 
  unsigned short id; /* Identificacio'n */ 
  unsigned short indicadores_despfragmento; /* 3 bits de indicadores, 13 bits de fragmento */ 
  unsigned char ttl; /* Tiempo de vida */ 
  unsigned char protocolo; /* protocolo */ 
  unsigned short suma; /* Suma de comprobacio'n (checksum) de la cabecera */ 
  tdireccion_ip dir_origen; /* direccio'n IP del origen */ 
  tdireccion_ip dir_destino; /* direccio'n IP del destino */ 
  unsigned int opciones_relleno; /* 24 bits opciones y 8 de relleno */ 
  unsigned char *datos; 
} tdatagrama_ip; 
 
typedef struct{ 
  unsigned  char direccion_origen[6];//6 B
  unsigned char direccion_destino[6];//6 B
  unsigned short tipo;//2 B
} ttrama_ethernet;     

ip_mostrar(tdatagrama_ip datagrama) { 
  int i;
  char buffer[256];
  struct protoent *es_protocolo;
  printf(" 0                   1                   2                   3\n"); 
  printf(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n"); 
  printf("+-Ver---+-HL----+-TOS-----------+-Longitud----------------------+\n"); 
  /*       version  IHL     tos             longitud */ 
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
 
typedef struct{
    int icmp;
    int udp;
    int telnet;
    int ftp;
    int desconocidos;
    int tcp;
} estadisticas;

estadisticas e;

void aumentar_carga(tdatagrama_tcp* datagrama, tdatagrama_ip* dat_ip, bpf_u_int32 len){
    int i = 0;
    int encontrado = 0;
    for (i = utiles-1; i>=0 && !encontrado; i--){
            if (comparar_tramas(datagrama, dat_ip->dir_origen, dat_ip->dir_destino, i) == 1){
                c[i].carga += len - sizeof (ttrama_ethernet) - 4 * (dat_ip->version_longcabecera & 0x0F) - 4 * (ntohs(datagrama->offset_reserved_y_flags) >> 12);
            }

    }
}
int es_conexion(unsigned char flags){
    if (((flags & 0x02) != 0)  && (flags & 0x10) == 0){//es SYN y no ACK. Creamos la conexion
        return 1;
    }
    else if ((((flags&0x02)!=0) && ((flags&0x10) != 0)) || ((flags&0x01)!= 0) || (((flags&0x10 )!= 0) && ((flags&0x01)!= 0)))//SYN + ACK o FIN o FIN+ACK
        return 2;
    else if ((flags & 0x02) == 0 && (flags & 0x10) != 0){//comienza la transmision de datos ACK & no SYN
        return 3;
        }
}

int aumentar_paso(tdatagrama_tcp* datagrama, tdireccion_ip origen, tdireccion_ip destino){
    int i;
    int encontrado = 0;
    for (i = utiles-1; i>=0 && !encontrado; i--){
        if (comparar_tramas(datagrama, origen, destino,i) == 1){
            if (c[i].paso < 6){
                c[i].paso++;
                encontrado=1;
                if (c[i]. paso == 2 || c[i].paso == 5){
                    c[i].paso++;
                }
            }
        }
    }
    
}

void iniciar_conexion(tdatagrama_tcp *datagrama, tdireccion_ip orig, tdireccion_ip destino){
    c[utiles].ipdest = destino;
    c[utiles].iporig = orig;
    c[utiles].pdest = datagrama->destport;
    c[utiles].porig = datagrama->sourceport;
    c[utiles].paso = 1;
    utiles++;
}
int comparar_tramas(tdatagrama_tcp* datagrama, tdireccion_ip origen, tdireccion_ip destino, int i){
    if ((c[i].iporig.byte1 == origen.byte1)
        && (c[i].iporig.byte2 == origen.byte2)
        && (c[i].iporig.byte3 == origen.byte3)
        && (c[i].iporig.byte4 == origen.byte4)
        && (c[i].ipdest.byte1 == destino.byte1)
        && (c[i].ipdest.byte2 == destino.byte2)
        && (c[i].ipdest.byte3 == destino.byte3)
        && (c[i].ipdest.byte4 == destino.byte4)
        && (c[i].porig == datagrama->sourceport)
        && (c[i].pdest == datagrama->destport)){
        return 1;
    }
    else if((c[i].iporig.byte1 == destino.byte1)
        && (c[i].iporig.byte2 == destino.byte2)
        && (c[i].iporig.byte3 == destino.byte3)
        && (c[i].iporig.byte4 == destino.byte4)
        && (c[i].ipdest.byte1 == origen.byte1)
        && (c[i].ipdest.byte2 == origen.byte2)
        && (c[i].ipdest.byte3 == origen.byte3)
        && (c[i].ipdest.byte4 == origen.byte4)
        && (c[i].porig == datagrama->destport)
        && (c[i].pdest == datagrama->sourceport)){
        return 1;
    }
        
    else{
        return 0;
    }
}
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);//He añadido a la cabecera 
void recoger_datos_estadisticos(const char*);
int mostrar_datos_estadisticos(char* protocolo);
void tcp_mostrar(tdatagrama_tcp* datagrama);
void udp_mostrar(tdatagrama_udp* datagrama);
void icmp_mostrar(tdatagrama_icmp* datagrama);

int mostrar_interfaces_disponibles(void){ 
  int n_interfaces=0;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];
  printf(" Dispositivos disponibles:\n\n"); 
  /* Obtiene la lista de dispositivos: */ 
  if (pcap_findalldevs(&alldevs, errbuf) == -1 ){
      fprintf(stderr,"Error al ejecutar pcap_findalldevs");
  }
  /* Print the list */ 
  for(d=alldevs;d!=NULL;d=d->next){
      printf("\t- [%s]", d->name);
      if (d->description)
      printf(" (%s)\n", d->description);
      else
      printf(" (No hay descripción disponible)\n");
      i++;
  }
  if(i==0) 
    {
      printf("\nNo se encontraron dispositivos válidos.\n"); 
      return;
    } 
 
  /* We don't need any more the device list. Free it */ 
  pcap_freealldevs(alldevs);
  return n_interfaces;
} 

int main(int argc, char **argv) { 
  estadisticas e;
  struct bpf_program filtro; 
  bpf_u_int32 mascara_red, direccion_red; 
  pcap_t *fp; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  int tipo=-1;
  if(argc < 2){ 
 
    fprintf(stderr,"Sintaxis:\n\t%s -i <interfaz de red> [filtro]\n\t%s -f <fichero de volcado> [filtro]\n\t%s -l\n\t%s -si <interfaz de red> [filtro]\n\t%s -sf <fichero de entrada> [filtro]\n", argv[0],argv[0],argv[0],argv[0],argv[0]); 
    return (-1); 
 
  } 

  switch(argv[1][1]){ 
  case 'i': 
    if(argc<3){
    fprintf(stderr,"Error en el paso de argumentos.\n\tSintaxis: %s -i <interfaz de red> [filtro]\n",argv[0]);   
    return 1;
    }
    //Compruebo que el dispositivo sea correcto
    
    if(check_device(argv[2])!=0){
        tipo=TIPO_EN_VIVO; 
        fp=pcap_open_live(argv[2],BUFSIZ,1,0,errbuf);
    }
    else{ 
        fprintf(stderr,"Error 4A: no existe el dispositivo %s\n",argv[2]);   
        return 1;
    }
    break; 
 
  case 'f':
 
    if(argc<3) 
      return 1; 
 
    tipo=TIPO_EN_FICHERO; 
    /* Apertura del fichero de captura */ 
    /* ***Usar***  pcap_open_offline */ 
    fp = pcap_open_offline(argv[2],errbuf);
    if (fp == NULL){
        fprintf(stderr,"Error al abrir el fichero");
    }
    if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1 ){//con fichero, cnt = 0
                    fprintf(stderr, "Error al capturar paquetes\n");
                    return 1;
    }
    int i = 0;
    int correctas = 0, incorrectas = 0;
    for (i = 0; i<utiles; i++){
        printf("CONEXION %i\n", i);
         printf("IP origen: %3d.%3d.%3d.%3d \n",
                c[i].iporig.byte1,
                c[i].iporig.byte2,
                c[i].iporig.byte3,
                c[i].iporig.byte4);

        printf("IP destino: %3d.%3d.%3d.%3d \n",
                c[i].ipdest.byte1,
                c[i].ipdest.byte2,
                c[i].ipdest.byte3,
                c[i].ipdest.byte4);

        printf("Puerto de origen: %d \n", c[i].porig);
        printf("Puerto de destino: %d \n", c[i].pdest);
        if (c[i].paso == 6){
            correctas++;
        }
        else
            incorrectas++;
        printf("Carga de la trama %i: %lu\n",i, c[i].carga);
        if (c[i].paso == 6){
            printf("Conexion correcta\n\n\n");
        }
        else{
            printf("Conexion incorrecta\n\n\n");
        }
    }
    printf("Correctas: %i\n",correctas);
    printf("Incorrectas: %i\n", incorrectas);
    return 0;
 
    break; 
 
  case 'l': 
        
    return mostrar_interfaces_disponibles(); 
    break;
    
  case 's':
      switch(argv[1][2]){
          case 'f':
                fp = pcap_open_offline(argv[2],errbuf);
                if (fp == NULL){
                        fprintf(stderr,"Error al abrir el fichero\n");
                }
                if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1 ){//con fichero, cnt = 0
                    fprintf(stderr, "Error al capturar paquetes\n");
                    return 1;
                }else {
                    return mostrar_datos_estadisticos(argv[3]);
                }                
          break;
          case 'i':
              if(argc<3){
                fprintf(stderr,"Error en el paso de argumentos.\n\tSintaxis: %s -si <interfaz de red> [filtro]\n",argv[0]);   
                return 1;
              }
              //Compruebo que el dispositivo sea correcto
   
            if(check_device(argv[2])!=0){
                tipo=TIPO_EN_VIVO; 
                fp=pcap_open_live(argv[2],BUFSIZ,1,0,errbuf);
            }
            else{ 
                fprintf(stderr,"Error 4A: no existe el dispositivo %s\n",argv[2]);   
                return 1;
            }
            while(1){
                pcap_loop(fp,20,dispatcher_handler, NULL);//desde interfaz, cnt = 100, pero pongo 20 porque si no nos morimos esperando
                mostrar_datos_estadisticos(argv[3]);
                sleep(5);
            }
          break;
          default: 
            fprintf(stderr,"Error: opción -%c no válida.\n",argv[1][2]); 
            return 1; 
          break; 
      }
  default: 
    fprintf(stderr,"Error: opción -%c no válida.\n",argv[1][1]); 
    return 1; 
    break; 
  } 
 
  /* En caso de que se haya especificado un filtro: */ 
  if(argc>3){ 
    /* Obtenemos cuál es la máscara de red asociada al dispositivo abierto: */ 
        if(pcap_lookupnet(argv[2], &direccion_red, &mascara_red, errbuf) == -1){
            fprintf (stderr, "Error al asignar el filtro");
        }

    /* Compilamos la expresión en "filtro": */ 
        if(pcap_compile(fp, &filtro, argv[3], 0, mascara_red) == -1){
            fprintf (stderr, "Error al compilar el filtro\n");
        }

    /* Establecemos un filtro para el tráfico: */  
 
        if(pcap_setfilter(fp, &filtro) == -1){
            fprintf(stderr, "Error al asignar el filtro\n");
        }
     
    printf("Asignado filtro \"%s\"\n",argv[3]); 
  } 
 
  /* Lee y procesa tramas hasta que se llegue a EOF. */ 
  if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1){
      fprintf(stderr, "Error al capturar paquetes");
  }
    int i = 0;
    for (i = 0; i<utiles; i++){
        if ((c[i].paso % 6) != 0)
            printf("Conexion erronea");
        else
            printf("Conexion correcta");
    }
  return 0; 
} 
 
 
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
  u_int i=0;
  tdatagrama_ip *datagrama;
  tdatagrama_tcp *datagrama_tcp;
  tdatagrama_udp *datagrama_udp;
  tdatagrama_icmp *datagrama_icmp;
  ttrama_ethernet *trama;
  unsigned char longitud;
  /* print pkt timestamp and pkt len */
  //printf("%ld : %ld (%ui)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
  /* Comprobamos que sea un datagrama IP */
  trama=(ttrama_ethernet *)(pkt_data);
  if(ntohs(trama->tipo)== ETHERTYPE_IP){ 
    datagrama=(tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet));
    //ip_mostrar(*datagrama);
    longitud = 4*(datagrama->version_longcabecera & 0x0F);
    if (strcmp((getprotobynumber(datagrama->protocolo)->p_name),"tcp")==0){
        datagrama_tcp = (tdatagrama_tcp *) (pkt_data+sizeof(ttrama_ethernet)+longitud);
        datagrama_tcp->destport = ntohs(datagrama_tcp->destport);
        datagrama_tcp->sourceport = ntohs(datagrama_tcp->sourceport);
        int conexion;
        conexion = es_conexion((ntohs(datagrama_tcp->offset_reserved_y_flags)) & 0x001F);
        if (conexion == 1){
            iniciar_conexion(datagrama_tcp, datagrama->dir_origen, datagrama->dir_destino);
        }
        else if(conexion == 2){
            aumentar_paso(datagrama_tcp, datagrama->dir_origen, datagrama->dir_destino);
        }
        else if (conexion == 3){
            aumentar_carga(datagrama_tcp, datagrama, header->len);
        }
        if (datagrama_tcp->destport == 23 || datagrama_tcp->sourceport == 23){//telnet
            recoger_datos_estadisticos("telnet");
        }
        else if(datagrama_tcp->destport == 21 || datagrama_tcp->destport == 20 || datagrama_tcp->sourceport == 21 || datagrama_tcp->sourceport == 20){//ftp
            recoger_datos_estadisticos("ftp");
        }
        recoger_datos_estadisticos("tcp");
        
        //comprobar si es una trama de tipo 2 o tipo 3. si lo son, recorrer el struct cuadrupla
        //comparando ip's y puertos y si coincide con alguna, aumentar paso++. al final, recorrer el struct entero y ver si
        //algun paso es menor de 3; si lo es, será una conexión fallida.
        //tcp_mostrar(datagrama_tcp);
    }
    else if(strcmp(getprotobynumber(datagrama->protocolo)->p_name,"udp")==0){
        datagrama_udp = (tdatagrama_udp *) (pkt_data + sizeof(ttrama_ethernet)+longitud);
        recoger_datos_estadisticos("udp");
        //udp_mostrar(datagrama_udp);
    }
    else if(strcmp(getprotobynumber(datagrama->protocolo)->p_name,"icmp")==0){
        datagrama_icmp = (tdatagrama_icmp *) (pkt_data + sizeof(ttrama_ethernet)+longitud);
        recoger_datos_estadisticos("icmp");
        //icmp_mostrar(datagrama_icmp);
    }
  }
  else{
      //fprintf(stderr, "No es un datagrama ip");
  }

}

int check_device(const char* name){
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1 ){
      fprintf(stderr,"Error al ejecutar pcap_findalldevs dentro de check_device\n");
    }
 
    for(d=alldevs;d!=NULL;d=d->next){
        if(strcmp(name,d->name)==0){
            return 1;
        }
    }
    return 0;
}

void recoger_datos_estadisticos(const char* c){
    if(strcmp(c,"icmp") == 0){
        e.icmp++;
    }else if(strcmp(c,"telnet") == 0){
        e.telnet++; 
    }else if(strcmp(c,"udp") == 0){
        e.udp++;
    }else if(strcmp(c,"ftp") == 0){
        e.ftp++;
    }else if(strcmp(c,"tcp")==0){
        e.tcp++;
    }else printf("Protocolo desconocido");
}

int mostrar_datos_estadisticos(char* protocolo){
    printf("\n \n \n");
    int total = e.icmp + e.udp + e.tcp +e.desconocidos;
    printf("Numero total de paquetes: %d\n",total);
    printf("ICMP: %d\n",e.icmp);
    printf("UDP: %d\n",e.udp);
    printf("TELNET: %d\n",e.telnet);
    printf("FTP: %d\n",e.ftp);
    printf("TCP: %d\n",e.tcp);
    printf("DESCONOCIDOS: %d\n",e.desconocidos);
    if(strcmp(protocolo,"tcp") == 0){
        printf("TCP aqui vale: %d",e.tcp);
        return e.tcp;
    }else
        if(strcmp(protocolo,"icmp") == 0){
            return e.icmp;
    }else
        if(strcmp(protocolo,"ftp")==0){
            return e.ftp;
    }else
        if(strcmp(protocolo,"telnet") == 0){
            return e.telnet;
    }else
        if(strcmp(protocolo,"udp")==0){
            return e.udp;
    }else return -1;
                    
                    
}

void udp_mostrar(tdatagrama_udp* datagrama){
    printf("TRAMA UDP:\n");
    printf("Puerto origen : %u\n",ntohs(datagrama->sourceport));
    printf("Puerto Destino: %u\n",ntohs(datagrama->destport));
    printf("Longitud: %u\n",ntohs(datagrama->longitud));
    printf("Suma de control: 0x%x\n",ntohs(datagrama->checksum));
}

void icmp_mostrar(tdatagrama_icmp* datagrama){
    printf("TRAMA ICMP:\n");
    printf("Tipo: %u\n",datagrama->tipo);
    printf("Codigo: %u\n",datagrama->codigo);
    printf("Suma de control: 0x%x\n",ntohs(datagrama->checksum));
    printf("Identificador: 0x%x\n", ntohs(datagrama->identificador));
    printf("Numero de Secuencia: 0x%x\n",ntohs(datagrama->num_secuencia));
}

void tcp_mostrar(tdatagrama_tcp* datagrama){
    printf("TRAMA TCP:\n");
    datagrama->offset_reserved_y_flags = ntohs(datagrama->offset_reserved_y_flags);
    datagrama->options_y_padding = ntohl(datagrama->options_y_padding);
    printf("Puerto origen : %u\n",datagrama->sourceport);
    printf("Puerto Destino: %u\n",datagrama->destport);
    printf("Numero de secuencia: 0x%x\n",ntohl(datagrama->numsecuencia));
    printf("Numero de confirmacion: 0x%x\n",ntohl(datagrama->ack));
    printf("Desplazamiento: %d\n",(datagrama->offset_reserved_y_flags & 0xF000)>>12);
    printf("Reservado: %u\n",(datagrama->offset_reserved_y_flags & 0x0FC0)>>6);
    printf("Flags: 0x%x\n",datagrama->offset_reserved_y_flags  & 0x002F);
    printf("Ventana: 0x%x\n",ntohs(datagrama->window));
    printf("Suma de control: 0x%x\n",ntohs(datagrama->checksum));
    printf("Puntero urgente: %u\n",ntohs(datagrama->pointer));
    printf("Opciones: %d\n",(datagrama->options_y_padding & 0xFFF0)>>4);
    printf("Padding: %d\n",datagrama->options_y_padding & 0x000F);
}