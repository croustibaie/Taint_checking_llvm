#include <unistd.h>
#include  <fcntl.h>

int main() {
    int i = 0;
    int* ip = &i;

    ssize_t nwritten = write(STDOUT_FILENO, &ip, sizeof(ip));

    return 0;
}
