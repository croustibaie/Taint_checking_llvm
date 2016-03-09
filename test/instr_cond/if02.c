int g(int x) {
    return x+4;
}

int f(int b) {
    if ((b+b) == (b+5)) {
        return g(3);
    }
    return g(1);
}

int main() {
    int i = 0;
    return f(i);
}
