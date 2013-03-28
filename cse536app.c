

/*
  Hello World
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAX_IP_STR 13

enum {
  FALSE = 0, TRUE =1};

int receiver_mode = FALSE;

char dest_ip_str[MAX_IP_STR];
char* data_to_send = NULL;
int data_to_send_size = 0;

// File handle to write to
FILE *fd = NULL;
const int IP_ADDRESS_SIZE = sizeof(uint32_t);

void processArgs(int argc, char** argv)
{
  printf("Processing %d arguments\n", argc-1);
  char c = 0;
  while((c =getopt(argc, argv, "rd:o:")) != -1)
  {

    switch(c)
    {

      case 'r':
        receiver_mode = TRUE;
        break;

      case 'd':
        strncpy(dest_ip_str, optarg, MAX_IP_STR);
        receiver_mode = FALSE;
        printf("Found destination ip: %s\n", 
            dest_ip_str);
        break;

      case 'o':
        if(optarg != NULL)
        {
          data_to_send_size = strlen(optarg) +
              IP_ADDRESS_SIZE+1;
          data_to_send = (char*)calloc(
              data_to_send_size, 1);
          strncpy(data_to_send, optarg, data_to_send_size-1);
          printf("Found data: %s\n", data_to_send);
          printf("Found data length: %zu\n", strlen(data_to_send));
        }
        break;

      default:
        printf("getopt error code: 0%o??\n", c);
    }
  }

}

//***************************************************************
FILE* openDev(const char* mode)
{

  fd = NULL;

  fd = fopen("/dev/cse5361", mode);
  if (!fd || ferror(fd))
  { 
    printf("File error opening file:%s\n",
        strerror(errno));
    exit(1);
  }
  return fd;
}

//***************************************************************
/**
 *  Write output
 */

int writeOutput(uint32_t dest, char* data, int data_size)
{
  printf("Writing to dest: %04x, data: %s, size: %d\n",
      dest, data, data_size);

  size_t count = fwrite(&dest, 1, sizeof(dest), fd);
  count += fwrite(data, 1, data_size-sizeof(dest), fd);
  if(count <= 0)
  {
    if(ferror(fd))
    {

      printf("ERROR: Could not write to device!: %s\n",
          strerror(errno));
    }

  }
  printf("writen: %zd\n", count);
  return count;
}

//***************************************************************
/**
 *  Wait for packets
 */
void waitForPackets()
{
  char buffer[0xFF];
  int count = 0;
  while(1)
  {

    printf("Progam must be stopped to exit..."
        "Waiting for packets\n");

    count = fread(buffer, sizeof(buffer), 1, fd);

    if(count > 0)
    {
      printf("Read packet data string: %s\n", 
          buffer);
    }

    printf("Hex Data: ");
    int i;
    for(i = 0; i < count; i++)
    {
      printf("%02x", buffer[i]);

    }
  }

}

//***************************************************************
int main(int argc, char** argv)
{

  processArgs(argc, argv);

  fd = openDev("rb+");

  uint32_t daddr = 0;

  if(!receiver_mode)
  {
    if(strlen(dest_ip_str) <= 0)
    {
      printf("no destination IP set. Use -d IP_ADDRESS_STRING. "
          "Example ./cse536app -d 192.168.2.1\n");
      exit(1);
    }

    inet_pton(AF_INET, dest_ip_str, &daddr);
    writeOutput(daddr,data_to_send, data_to_send_size);
    fflush(fd);
    fclose(fd);
  }
  else
  {
    waitForPackets();
  }

  return EXIT_SUCCESS;
}



