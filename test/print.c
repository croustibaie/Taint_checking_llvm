#include <taintgrind.h>
#include <stdio.h>

void print(long a) {
  printf("In print: %ld\n", a);
}
