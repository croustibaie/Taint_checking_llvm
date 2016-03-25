int f(int a, int b) {
    return a > b;
}

int main() {
    int a = 4;
    int b = 5;
    return f(a, (int) &b);
}
