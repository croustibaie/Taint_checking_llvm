int main() {
    int ary[2];
    ary[0] = 4;
    ary[1] = 5;

    ary[((int) &ary) % 2] = 11;

    return ary[0];
}
