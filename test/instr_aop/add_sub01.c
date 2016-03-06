int main() {
    int i = 0;
    int* l = &i + 1;
    return *(l-1);
}
