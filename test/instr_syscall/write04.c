#include <unistd.h>
#include  <fcntl.h>

int main() {
    int i = 0;
    long ip = 0x000000000000ff00 & (long) (int) &i;

    ssize_t nwritten = write(STDOUT_FILENO, &ip, sizeof(ip));

    return 0;
}
