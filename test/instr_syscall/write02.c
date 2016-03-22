#include <unistd.h>
#include  <fcntl.h>

int main() {
    int i = 0;
    int* ips[2];
    ips[0] = 0;
    ips[1] = &i;

    ssize_t nwritten = write(STDOUT_FILENO, &ips, sizeof(ips));

    return 0;
}
