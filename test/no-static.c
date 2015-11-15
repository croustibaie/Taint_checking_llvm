int f(int x) {
    return x ? ((int) &x) : x;
}

int main() {
    return 0;
}
