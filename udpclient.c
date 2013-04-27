/*UDP Client Program using Berkley Sockets*/

/*Note: Run without the "Localhost" argument*/
/*Compile Command: cc -o udpc udpc.c -lnsl -lsocket .... it may not be necessary to list the libraries*/
/*Run Command: ./udpc */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#define SERVER_PORT 23456 
#define MAX_PENDING 5
#define MAX_LINE 256

int main(int argc, char *argv[])
{
   struct sockaddr_in client, server;
   struct hostent *hp;
   char buf[MAX_LINE];
   int len, ret, n;
   int s, new_s;

   bzero((char *)&server, sizeof(server));
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = INADDR_ANY;
   server.sin_port = htons(0);

   s = socket(AF_INET, SOCK_DGRAM, 0);
   if (s < 0)
   {
		perror("simplex-talk: UDP_socket error");
		exit(1);
   }

   if ((bind(s, (struct sockaddr *)&server, sizeof(server))) < 0)
   {
		perror("simplex-talk: UDP_bind error");
		exit(1);
   }

   hp = gethostbyname( "192.168.3.3" );
   if( !hp )
   {
      	fprintf(stderr, "Unknown host %s\n", "localhost");
      	exit(1);
   }

   bzero( (char *)&server, sizeof(server));
   server.sin_family = AF_INET;
   bcopy( hp->h_addr, (char *)&server.sin_addr, hp->h_length );
   server.sin_port = htons(SERVER_PORT); 

   while(fgets(buf, sizeof(buf), stdin))
   {
		buf[MAX_LINE-1] = '\0';
	      len = strlen(buf) + 1;
		n = strlen(buf);
	      ret = sendto(s, buf, n, 0,(struct sockaddr *)&server, sizeof(server));
		if( ret != n)
		{
			fprintf( stderr, "Datagram Send error %d\n", ret );
			exit(1);
		}
   }
   return 0;
}
