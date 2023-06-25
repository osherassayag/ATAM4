#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
//#include <syscall.h>
//#include <sys/ptrace.h>
#include <sys/types.h>
//#include <sys/wait.h>
//#include <sys/reg.h>
//#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>


#include "elf64.h"

#define SHT_RELA 11

unsigned long find_dynamic(char* funName, char* exeName)
{
    FILE *elf = fopen(exeName, "r");
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
    Elf64_Sym *symbol_table = NULL;
    Elf64_Shdr *section_header = NULL;
    char *symb_name = NULL;
    fread(elf_header, sizeof(Elf64_Ehdr), 1, elf);

    //Allocating space for section header table
    section_header = (Elf64_Shdr *) malloc(elf_header->e_shentsize * elf_header->e_shnum);

    //Reading section header table
    fseek(elf, elf_header->e_shoff, SEEK_SET);
    fread(section_header, elf_header->e_shentsize, elf_header->e_shnum, elf);
}