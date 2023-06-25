

#include <stdio.h>
#include "find_symbol.c"


int main(int argc, char *const argv[]) {

    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);

    if (err >= 0)
        printf("%s will be loaded to 0x%lx\n", argv[1], addr);
    else if (err == -2)
        printf("%s is not a global symbol! :(\n", argv[1]);
    else if (err == -1)
        printf("%s not found!\n", argv[1]);
    else if (err == -3)
        printf("%s not an executable! :(\n", argv[2]);
    else if (err == -4)
        printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
    return 0;
}

