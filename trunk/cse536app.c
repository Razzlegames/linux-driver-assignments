

/*
  Hello World
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main()
{
  FILE *fd = NULL;
  char buffer[128];
  size_t count;

  fd = fopen("/dev/cse5361", "wb");
  if (!fd || ferror(fd))
  { 
    printf("File error opening file:%s\n",
        strerror(errno));
    exit(1);
  }
  count = fread(buffer, 1, sizeof(buffer), fd);
  if (!count)
      printf("No data read\n");
  else
      printf("%s\n", buffer);

  char testbuff[] = "testing";
  count = fwrite(testbuff, 1, sizeof(testbuff), fd);
  if(count <= 0)
  {
    if(ferror(fd))
    {

      printf("ERROR: Could not write to device!: %s\n",
          strerror(errno));
    }

  }
  printf("writen: %zd\n", count);
  fflush(fd);
  fclose(fd);

  return EXIT_SUCCESS;
}
