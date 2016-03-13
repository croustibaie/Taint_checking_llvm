#include <string.h>
#include <unistd.h>
#include  <fcntl.h>

int main() {
    int i = 42;

    ssize_t nwritten = write(STDOUT_FILENO, &i, sizeof(i));

    return 0;
}
