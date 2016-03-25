int main() {
    int i = 4;
    long ip = (long) &i;
    long r = ip + ip;

    long a[2];
    a[0] = 7;
    a[1] = r;

    return a[1];
}
