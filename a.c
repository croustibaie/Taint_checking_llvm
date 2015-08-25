#include<stdio.h>
int main()
{

    int i =0;
    int *k = &i;
    long c= (long) k;
    printf("%ld\n", c);
    return 0;
}
