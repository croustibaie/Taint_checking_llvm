int f(int x) {
    return x == 0;
}

int main() {
    int i = 0;
    // allowed
    return f((int) &i);
}
