int f(int a, int b) {
    return a-b;
}

int main() {
    int x = 4;
    int y = 5;
    int* xp = &x;
    return f((int) xp, y);
}
