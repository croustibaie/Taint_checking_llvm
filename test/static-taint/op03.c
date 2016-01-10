int f(int a, int b) {
    return a == b;
}

int g(int a, int b) {
    return a != b;
}

int main() {
    int a = 0;
    int b = 0;
    
    return f((int) &a, (int) &b) || g((int) &a, (int) &b);
}
