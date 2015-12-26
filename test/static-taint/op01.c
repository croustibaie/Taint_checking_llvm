int main() {
    int a = 0;
    int b = 1;

    int* ap = &a;
    int* bp = &b;

    return (a + b) == a ? a*b : a/b; // all legal -> green taint
}
