

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
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>

#include "udpclient.h"
#include "cse5361.h"



enum {
  FALSE = 0, TRUE =1};

int receiver_mode = FALSE;

char dest_ip_str[MAX_IP_STR];
char* data_to_send = NULL;
int data_to_send_size = 0;

pthread_t read_thread;
pthread_t write_thread;

// File handle to write to
FILE *fd = NULL;
const int IP_ADDRESS_SIZE = sizeof(uint32_t);

//************************************************************************
void printMessage(const Message* message)
{


  /// Record ID
  printf(" record_id: %u\n", message->header.record_id);

  /// counter
  printf(" final_clock: %u\n", message->header.final_clock);

  /// counter
  printf(" orig_clock: %u\n", message->header.orig_clock);

  /// Source IP
  printf("__be32 source_ip: %u\n", message->header.source_ip);

  /// Dest IP
  printf(" dest_ip: %u\n", message->header.dest_ip);


  printf(" data: %s\n", message->data);

}


//***************************************************************
/**
 *  Handle all signals to program
 */
void int_handler(int sig)
{

  printf("Trying to quit...\n");
  printf("Closing any open file handles..\n");
  if(sig == SIGINT)
  {
    printf("SIGINT RECEIVED\n");
  }
  else if(sig == SIGHUP)
  {

    printf("SIGHUP RECEIVED\n");
  }
  fflush(stdout);
  if(fd && fclose(fd) != 0)
  {

    printf("ERROR: could not close device!\n");
    exit(1);

  }
  fd = NULL;
  exit(0);
}


//***************************************************************
/**
 *  Process all command line arguments
 */
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

int writeOutput(Message* message)
{

  printf("Writing to dest: %04x, data: %s, size: %zu\n",
      message->header.dest_ip, message->data, 
      sizeof(*message));

  size_t written = fwrite(message, 1, sizeof(*message), fd);
  fflush(fd);
  if(written <= 0)
  {
    if(ferror(fd))
    {

      printf("ERROR: Could not write to device!: %s\n",
          strerror(errno));
    }

  }
  printf("written: %zd\n", written);
  return written;
}

//***************************************************************
/**
 *  Wait for packets
 */
void waitForPackets()
{

  char buffer[257];
  int count = 0;
  printf("Progam must be stopped to exit...\n");
  while(1)
  {

    //    printf("Progam must be stopped to exit..."
    //        "Waiting for packets\n");

    count = fread(buffer, sizeof(buffer), 1, fd);

    if(count > 0)
    {
      printf("Read packet data string: %s\n", 
          buffer);

      printf("Hex Data: ");
      int i;
      for(i = 0; i < count; i++)
      {
        printf("%02x", buffer[i]);

      }
      printf("\n");
    }
  }

}

//***************************************************************
/**
 *  Randomize last octet of IP Address so we can 
 *    send to all folks in class
 */

void randomizeLastOctet(uint8_t* ip_ptr)
{

  int lower_octet = 0;
  lower_octet = rand() % 40 + 3;
  ip_ptr[3] = lower_octet;

}

//***************************************************************
/**
 *  Write mode
 */
void doWriteMode(void* arg)
{

  printf("Entered write mode!\n");

  // Message to send
  Message message;
  memset(&message, 0, sizeof(message));

  printf("Prep to send message of size: %zu\n",
      sizeof(message));
  fflush(stdout);

  message.header.record_id = EVENT_MESSAGE;

  // This part is just for testing 
  //   (need random IP for last octet in production)
  struct in_addr addr = {0};
  int result = 
    inet_aton("192.168.2.9", &addr);
  message.header.dest_ip = *(uint32_t*)&addr;

  if(result == 0)
  {

    printf("Error converting to binary ip!\n");
    exit(1);
  }

  // Just something stupid to send
  const char* greeting = "Hi packet";
  int i = rand() % 50;

  char str_addr[INET_ADDRSTRLEN] = "";

  // Write till we are quit by Ctrl-C
  while(1)
  {

    // Use only for the final testing phase in class
    //randomizeLastOctet((uint8_t*)&message.header.dest_ip);

    inet_ntop(AF_INET, &message.header.dest_ip, 
        str_addr, INET_ADDRSTRLEN);
    snprintf((char*)message.data, sizeof(message.data), 
        "%s: %d\n", greeting, i);

    printf("Written message was:[%s]: %s\n", 
        str_addr,
        (char*)message.data);
    printf("data size: %zu\n", sizeof(message.data));
    printf("Write mode!\n");
    printf("Transport packet size: %zu\n", sizeof(message));

    writeOutput(&message);
    fflush(stdout);
    sleep(1);
    i++;
  }

}

//***************************************************************
/**
 *  Read mode
 */
void* doReadMode(void* arg)
{

  Message message;
  strncpy((char*)message.data, 
      "Read the message!", sizeof(message.data));
  int count = 0;
  // Read till we are quit by Ctrl-C
  while(1)
  {
    count = fread(&message, sizeof(message), 1, fd);
    if(count > 0)
    {
      printf("-------------------------------------------\n");
      printf("Read message[%d] was: %s\n",
          count, message.data);
      printMessage(&message);
      printf("-------------------------------------------\n");
      sendToServer(&message);
    }
    fflush(stdout);
  }
  return NULL;
}

//***************************************************************
int main(int argc, char** argv)
{

  sighandler_t sighand;
  sighand = signal(SIGINT, int_handler);
  if(sighand == SIG_ERR)
  {
    printf("ERROR setting up signal handler: SIGINT\n");
  }

  sighand = signal(SIGHUP, int_handler);
  if(sighand == SIG_ERR)
  {
    printf("ERROR setting up signal handler: SIGHUP\n");
  }

  timeval seed_time;
  gettimeofday(&seed_time, NULL);
  srand(seed_time.tv_usec);

  //processArgs(argc, argv);

  fd = openDev("rb+");

  pthread_create(&read_thread, NULL, &doReadMode, NULL);

  // write mode
  doWriteMode(NULL);
  //    inet_pton(AF_INET, dest_ip_str, &daddr);
  //    writeOutput(daddr,data_to_send, data_to_send_size);

  fflush(fd);
  fclose(fd);

  return EXIT_SUCCESS;
}



