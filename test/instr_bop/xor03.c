int f(int a, int b) {
    return a^b;
}

int main() {
    int x = 4;
    int y = 5;
    int* yp = &y;
    return f(x, (int) yp);
}
