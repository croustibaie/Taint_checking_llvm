#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

int main() {
    int j = 0;
    
    int i[2];
    i[0] = 42;
    i[1] = 43;

    int* ips[2];
    ips[0] = 0;
    ips[1] = &j;

    struct iovec iov[2];
    ssize_t nwritten;

    iov[0].iov_base = &i;
    iov[0].iov_len = sizeof(i);
    iov[1].iov_base = &ips;
    iov[1].iov_len = sizeof(ips);
    
    nwritten = writev(STDOUT_FILENO, iov, 2);

    return 0;
}
