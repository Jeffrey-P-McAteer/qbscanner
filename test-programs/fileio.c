#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    printf("Reading %s\n", filename);
    
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open file");
        return 1;
    }
    
    char buf[100];
    if (fgets(buf, sizeof(buf), f)) {
        printf("First line: %s", buf);
    }
    
    fclose(f);
    return 0;
}