#include <stdio.h>
int main() {
    FILE *f = fopen("/tmp/test_file.txt", "r");
    char buf[100];
    if (f) {
        fgets(buf, sizeof(buf), f);
        printf("Read: %s", buf);
        fclose(f);
    }
    return 0;
}
