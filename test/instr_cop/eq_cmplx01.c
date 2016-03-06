int f(int x) {
    int y = 0;
    return (((int) &y) == x) ? 1 : 0;
}

int main() {
    int i = 0;
    return f(0) + f((int) &i);
}
