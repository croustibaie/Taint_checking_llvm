int f(int a, int b) {
    return (a + b) == a ? a*b : a/b;
}

int main() {
    return f(0, 1);    
}
