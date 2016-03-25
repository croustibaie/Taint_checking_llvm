#include <stdlib.h>

int f(long a) {
    return (a+a) == (a+5) ? 0 : 42;
}

int main() {
    int* a = malloc(sizeof(int)*3);
    return f((long) a);
}
