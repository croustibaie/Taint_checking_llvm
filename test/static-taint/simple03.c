int f(int x) {
    return x;
}

int main() {
    int i = 1;
    return f((int) &i);
}
