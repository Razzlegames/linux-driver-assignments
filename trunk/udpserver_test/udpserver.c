/*UDP Server Program using Berkley Sockets*/

/* Compile Command: cc -o udps udps.c -lnsl -lsocket */
/* Run Command: ./udps */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "cse5361.h"

#define SERVER_PORT 23456 
#define MAX_LINE 256

int main (int argc, char * argv[])
{
  struct hostent *hp;
  struct sockaddr_in server, client;
  char buf[MAX_LINE];
  int s, ret;
  int length=0;

  hp = gethostbyname("192.168.2.8");  // replace this ip with your host name or ip


  if (!hp)			
  {
    fprintf(stderr,"simplex-talk:Unknown host: %s\n",(char*)hp);
    exit(1);
  }

  bzero((char *)&server, sizeof(server));
  server.sin_family = AF_INET;
  bcopy(hp->h_addr, (char *)&server.sin_addr,hp->h_length);
  server.sin_port = htons(SERVER_PORT);

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("simplex_talk: socket error");
    exit(1);
  }

  ret = bind(s, (struct sockaddr *)&server, sizeof(server));
  if( ret < 0)
  {
    fprintf( stderr, "Bind Error: can't bind local address");
    exit(1);
  }

  length = sizeof(client);
  printf("-------------------------------------------\n");
  printf("     Starting UDP Test Server\n");
  printf("-------------------------------------------\n");
  fflush(stdout);

  while(1)
  {
    ret = recvfrom(s, buf, MAX_LINE, 0, 
        (struct sockaddr *)&client, (socklen_t*)&length);


    if( ret < 0 )
    {
      fprintf( stderr, "Receive Error %d\n", ret );
      exit(1);
    }


    Message* message = (Message*)buf;
    char ip_address[MAX_IP_STR];
    inet_ntop(AF_INET, &message->header.dest_ip, ip_address,
        MAX_IP_STR);

    printf("-------------------------------------------\n");
    if(message->header.record_id == 0)
    {
      printf("Message was a COMPLETE EVENT to: %s\n",
          ip_address);
    }
    else
    {

      printf("Message NO ACK RECEIVED!!!!: %s\n",
          ip_address);
    }
    printf("-------------------------------------------\n");
    printf( "Working!!!> %s", message->data);
  }
  return 0;
}
