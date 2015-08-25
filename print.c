#include "/usr/local/include/valgrind/taintgrind.h"
#include <stdio.h>

void print(long a)
{
  printf("In print: , %ld",a);
}

/*void print()
{
    printf("blalba \n");
}*/

