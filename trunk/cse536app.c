

/*
  Hello World
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main()
{
  FILE *fd = NULL;
  char buffer[128];
  size_t count;

  fd = fopen("/dev/cse5361", "rwb");
  if (!fd)
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
  fwrite(buffer, 1, 10, fd);
  fclose(fd);

  return EXIT_SUCCESS;
}
