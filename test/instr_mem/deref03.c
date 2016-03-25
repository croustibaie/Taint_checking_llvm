int main() {
    int ary[2];
    ary[0] = 4;
    ary[1] = 5;

    return ary[((int) &ary) % 2];
}
