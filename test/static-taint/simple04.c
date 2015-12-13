int f(int x) {
    return x ? (int) &x : 15;
}

int main() {
    return f(0);
}
