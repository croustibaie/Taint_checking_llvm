int f(int x);

int main() {
    int i = 1;
    int* ip = &i;
    return f(*ip - 1);
}

int f(int x) {
    return x;
}
