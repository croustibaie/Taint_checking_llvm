int f(int a) {
    return !a;
}

int main() {
    int x = 4;
    int* xp = &x;
    return f((int) xp);
}
