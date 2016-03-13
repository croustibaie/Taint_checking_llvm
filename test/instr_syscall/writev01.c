#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

int main() {
    int i = 0;
    int* ip = &i;
    struct iovec iov[2];
    ssize_t nwritten;

    iov[0].iov_base = &i;
    iov[0].iov_len = sizeof(i);
    iov[1].iov_base = &ip;
    iov[1].iov_len = sizeof(ip);
    
    nwritten = writev(STDOUT_FILENO, iov, 2);

    return 0;
}
