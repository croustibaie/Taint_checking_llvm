#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0;
    int j = i;
    int* k = &i;
    int* l = &i + 1;
    int* m = malloc(sizeof(int));
    long c = (long) k;
    printf("%ld\n", c);
    return 0;
}
