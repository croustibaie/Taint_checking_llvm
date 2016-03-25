#include <unistd.h>
#include  <fcntl.h>

void f(int a) {
    int d = ~a;
    ssize_t nwritten = write(STDOUT_FILENO, &d, sizeof(d));
}

int main() {
    int x = 4;
    f(x);
    return 0;
}
