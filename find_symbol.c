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

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file

#define SYMB_TABLE 0x2
#define STR_TAB 0x3
void free_all_and_close(FILE* elf, Elf64_Ehdr* elf_header, Elf64_Sym* symbol_table,  Elf64_Shdr* section_header , char* symb_name  )
{
    if(elf_header != NULL) free(elf_header);
    if(symbol_table != NULL) free(symbol_table);
    if(section_header != NULL) free(section_header);
    if(symb_name != NULL) free(symb_name);
    fclose(elf);
}

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    FILE *elf = fopen(exe_file_name, "r");
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
    Elf64_Sym *symbol_table = NULL;
    Elf64_Shdr *section_header = NULL;
    char *symb_name = NULL;
    fread(elf_header, sizeof(Elf64_Ehdr), 1, elf);

    if (elf_header->e_type != ET_EXEC) { //If the file isn't an executable
        *error_val = -3;
        free_all_and_close(elf, elf_header, symbol_table, section_header, symb_name);
        return 0;
    }
    //Allocating space for section header table
    section_header = (Elf64_Shdr *) malloc(elf_header->e_shentsize * elf_header->e_shnum);

    //Reading section header table
    fseek(elf, elf_header->e_shoff, SEEK_SET);
    fread(section_header, elf_header->e_shentsize, elf_header->e_shnum, elf);

    //Searching for symbol table & string table offset
    int offset = 0, index = 0, strtab_offset = 0;

    for (int i = 0; i < elf_header->e_shnum; i++) {
	
        if ((section_header + i)->sh_type == SYMB_TABLE) {
            symbol_table = (Elf64_Sym *) malloc(section_header[i].sh_size * section_header[i].sh_entsize);
            index = i;
            offset = section_header[i].sh_offset;
            strtab_offset = offset + section_header[i].sh_size;
        } 
    if ((section_header + i)->sh_type == STR_TAB && i != elf_header->e_shstrndx) {
            strtab_offset = section_header[i].sh_offset;
        } 

    }
 

    //Reading symbol table
    unsigned long num_of_entries = section_header[index].sh_size / section_header[index].sh_entsize;
    fseek(elf, offset, SEEK_SET);

    fread(symbol_table, section_header[index].sh_entsize, num_of_entries, elf);

    unsigned long address = 0;
    bool found_global = false, found_local = false;
    char character;
    int len = 0;
    //Searching for the symbol

    for (int i = 0; i < num_of_entries; ++i) {
        len = 0;
        fseek(elf, symbol_table[i].st_name + strtab_offset, SEEK_SET);
        while (fgetc(elf)) len++;
        fseek(elf, symbol_table[i].st_name + strtab_offset, SEEK_SET);
        if (symb_name == NULL) {
            symb_name = (char *) malloc(len * sizeof(char));
        } else {
            free(symb_name);
            symb_name = (char *) malloc(len * sizeof(char));
        }
        for (int j = 0; j < len; j++) {
            symb_name[j] = fgetc(elf);
        }





        //If we've found a match in the name
        if (strcmp(symb_name, symbol_name) == 0) {


            //Checking if it's global or local
            if(ELF64_ST_BIND(symbol_table[i].st_info) == 1) { //If it's global
                found_global = true;
                //Checking where it was defined
                if(symbol_table[i].st_shndx == 0 ) //If it's undefined
                {
                    *error_val = -4;
                    free_all_and_close(elf, elf_header, symbol_table, section_header, symb_name);
                    return 0;
                }
                //We've found the symbol, it's global and defined
                *error_val = 1;
                address = symbol_table[i].st_value;
                free_all_and_close(elf, elf_header, symbol_table, section_header, symb_name);
                return address;
            }
            if(ELF64_ST_BIND(symbol_table[i].st_info) == 0) { //If it's local
                found_local = true;
            }

        }

    }

    if (!found_local && !found_global) { //Symbol not found
        *error_val = -1;
        free_all_and_close(elf, elf_header, symbol_table, section_header, symb_name);
        return 0;
    }

    //Only option left - symbol was found but only as a local symbol
    *error_val = -2;
    free_all_and_close(elf, elf_header, symbol_table, section_header, symb_name);
    return 0;


}
