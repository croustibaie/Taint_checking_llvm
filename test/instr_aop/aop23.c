int f(int a) {
    --a;
    return a;
}

int main() {
    int x = 4;
    int* xp = &x;
    return f((int) xp);
}
