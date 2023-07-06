

#include <stdio.h>
//#include "find_symbol.c"
//#include "find_dynamic.c"
#include <sys/ptrace.h>
//#include <user.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
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
#define SHT_RELA 4
#define SHT_DYNSYM 11
#define STR_TAB 3
#define SYMB_TABLE 2





//----------------------FIND SYMBOL------------------------------------------------


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
Elf64_Addr find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
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
            //strtab_offset = offset + section_header[i].sh_size;
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







//---------------------------------FIND DYNAMIC -------------------------------------
void free_and_close(FILE* elf, Elf64_Ehdr* elf_header, Elf64_Sym* symbol_table, Elf64_Shdr* section_header , char* symb_name,
                    Elf64_Rela* rela);
Elf64_Addr find_dynamic(char* funName, char* exeName)
{

    /**
     *
    Todo: Find relocation tables. Find dynamic symbol table. Find dynamic string table.
    iterate over each entry in every relocation section. read the symbol field in each entry
     using the ELF64_R_SYM macro. go to the corresponding entry in the dynsym table, and from there go to the
     dynstr table to verify that the correct symbol has been found. Once we've done that,
     Go to the GOT (?) and retrieve the address, deduct 6 because before the dynamic linking, the address in the GOT points to
     the next command
    */
    FILE *elf = fopen(exeName, "r");
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
    Elf64_Sym *dyn_symb = NULL;
    Elf64_Shdr *section_header = NULL;
    Elf64_Rela *rela_plt = NULL;
    fread(elf_header, sizeof(Elf64_Ehdr), 1, elf);

    //Allocating space for section header table
    section_header = (Elf64_Shdr *) malloc(elf_header->e_shentsize * elf_header->e_shnum);

    //Reading section header table
    fseek(elf, elf_header->e_shoff, SEEK_SET);
    fread(section_header, elf_header->e_shentsize, elf_header->e_shnum, elf);


    //Searching for symbol table & string table offset
    int offset = 0, index = 0, dyn_strtab_offset = 0, len = 0;
    char* str_table_name = NULL;
    for (int i = 0; i < elf_header->e_shnum; i++) {
        //Finding the dynamic symbol table
        if (ELF64_ST_TYPE(section_header[i].sh_type) == SHT_DYNSYM) {

            dyn_symb = (Elf64_Sym *) malloc(section_header[i].sh_size * section_header[i].sh_entsize);
            index = i;
            offset = section_header[i].sh_offset;
            dyn_strtab_offset = offset + section_header[i].sh_size;
        }
        /*Finding the dynamic string table
        if ((section_header + i)->sh_type == STR_TAB && i != elf_header->e_shstrndx) {
            fseek(elf, section_header[i].sh_name + elf_header->e_shstrndx, SEEK_SET);
            while (fgetc(elf)) len++;
            fseek(elf, section_header[i].sh_name + elf_header->e_shstrndx, SEEK_SET);
            if (str_table_name == NULL) {
                str_table_name = (char *) malloc(len * sizeof(char));
            } else {
                free(str_table_name);
                str_table_name = (char *) malloc(len * sizeof(char));
            }
            for (int j = 0; j < len; j++) {
                str_table_name[j] = fgetc(elf);
            }
            if(strcmp(str_table_name, ".dynstr") == 0) {
		printf("Found Dynamic string table\n");
                dyn_strtab_offset = section_header[i].sh_offset;
                free(str_table_name);
            }
        } */

    }

    //Reading symbol table
    unsigned long num_of_entries = section_header[index].sh_size / section_header[index].sh_entsize;
    fseek(elf, offset, SEEK_SET);
    fread(dyn_symb, section_header[index].sh_entsize, num_of_entries, elf);

    //The name of the symbol we're looking for
    char* symb_name = NULL, *rela_name = NULL;
    //The index in the dynsym table
    unsigned long dyn_index = 0;
    int dyn_offset = 0;

    //Now going over the reallocation sections
    for (int i = 0; i < elf_header->e_shnum; i++) {
        //Finding the rela.plt section

        if (ELF64_ST_TYPE(section_header[i].sh_type) == SHT_RELA) {
		printf("Found rela\n");
                rela_plt = (Elf64_Rela *) malloc(section_header[i].sh_size * section_header[i].sh_entsize);
                fseek(elf, section_header[i].sh_offset, SEEK_SET);
                num_of_entries = section_header[i].sh_size / section_header[i].sh_entsize;
                fread(rela_plt, section_header[index].sh_entsize, num_of_entries, elf);
                for (int j = 0; j < num_of_entries; ++j) {
                    dyn_index = ELF64_R_SYM(rela_plt[j].r_info);
		    printf("index = %ld\n", dyn_index);
                    len = 0;
                    fseek(elf, dyn_symb[dyn_index].st_name + dyn_strtab_offset, SEEK_SET);
                    while (fgetc(elf)) len++;

                    fseek(elf, dyn_symb[dyn_index].st_name + dyn_strtab_offset, SEEK_SET);
                    if (symb_name == NULL) {
                        symb_name = (char *) malloc(len * sizeof(char));
                    } else {
                        free(symb_name);
                        symb_name = (char *) malloc(len * sizeof(char));
                    }
                    for (int k = 0; k < len; k++) {
                        symb_name[k] = fgetc(elf);
                    }
		    printf("Function name: %s\nSymbol name: %s\n", funName, symb_name);
                    if (strcmp(symb_name, funName) == 0) {
			printf("Found function %s\n", symb_name);
                        dyn_offset = rela_plt[j].r_offset;
			printf("offset = 0x%lx\n", rela_plt[j].r_offset);

                        free_and_close(elf, elf_header, dyn_symb, section_header, symb_name, rela_plt);
                        return dyn_offset;
                    }
                }

        }
        //Shouldn't get here

    }
    return 0;




}

void free_and_close(FILE* elf, Elf64_Ehdr* elf_header, Elf64_Sym* symbol_table, Elf64_Shdr* section_header , char* symb_name,
                    Elf64_Rela* rela)
{
    if(elf_header != NULL) free(elf_header);
    if(symbol_table != NULL) free(symbol_table);
    if(section_header != NULL) free(section_header);
    if(symb_name != NULL) free(symb_name);
    if(rela != NULL) free(rela);
    fclose(elf);
}



//----------------------------------MAIN---------------------------------------
pid_t run_target(char* const exe_name);

int main(int argc, char *const argv[]) {
    bool dynamic = false;
    printf("Symbol = %s\n", argv[1]);
    int err = 0;
    Elf64_Addr addr = find_symbol(argv[1], argv[2], &err);
    if (err == -3) {
        printf("%s not an executable! :(\n", argv[2]);
        return 0;
    }
    if (err == -1) {
        printf("%s not found! :(\n", argv[1]);
        return 0;
    }
    if (err == -2) {
        printf("%s is not a global symbol! :(\n", argv[1]);
        return 0;
    }

    //Symbol will come from shared library
    if (err == -4) {
	dynamic = true;
	printf("Searching dynamic\n");
        addr = find_dynamic(argv[1], argv[2]);
    }
    printf("The address is 0x%lx\n", addr);



    pid_t childPid = run_target(argv[2]);
    unsigned long call_counter = 0;
    int wait_status;
    struct user_regs_struct regs;
    unsigned long newAddr = addr;
    unsigned long long rsp;
    long data, rspAddr, rspData;
    waitpid(childPid, &wait_status, 0);
    if(dynamic) {
        newAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void*)addr, NULL);
        newAddr -= 6;
    }
    bool isFuncStart = false;
    while(WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, childPid, 0, &regs);
        if(isFuncStart)
        {
            ptrace(PTRACE_POKETEXT, childPid, (void*) newAddr, (void *) data);
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, childPid, 0, &regs);
            rspAddr= regs.rsp;
            rsp = ptrace(PTRACE_PEEKTEXT, childPid, (void*) rspAddr, NULL);
            rspData =  ptrace(PTRACE_PEEKTEXT, childPid, (void*)rsp, NULL);
            unsigned long rsp_trap = (rspData & 0xFFFFFFFFFFFFFF00) | 0xCC;
            ptrace(PTRACE_POKETEXT, childPid, (void*)rsp, (void*) rsp_trap);
            isFuncStart = false;
        }

        else {
            if(call_counter > 0) {
                if(call_counter == 1 && dynamic) {
                    newAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void*)addr, NULL);

                }
                if(rspAddr < regs.rsp) {
                    printf("PRF:: run #%ld returned with %d\n", call_counter, (int)regs.rax);
                    ptrace(PTRACE_POKETEXT, childPid, (void*)rsp, (void*)rspData);
                    regs.rip -=1;
                    ptrace(PTRACE_SETREGS, childPid, 0, &regs);
                    data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)newAddr, NULL);

                    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
                    ptrace(PTRACE_POKETEXT, childPid, (void*)newAddr, (void*)data_trap);
                    call_counter++;
                    isFuncStart = true;
                }
                else{
                    unsigned long current_data = ptrace(PTRACE_PEEKTEXT, childPid, (void*) rsp, NULL);
                    ptrace(PTRACE_POKETEXT, childPid, (void*)rsp, rspData);
                    regs.rip -= 1;
                    ptrace(PTRACE_SETREGS, childPid, 0, &regs);
                    if(ptrace(PTRACE_SINGLESTEP, childPid, NULL, NULL) < 0)
                    {
                        perror("error");
                        return 0;
                    }
                    waitpid(childPid, &wait_status, 0);
                    ptrace(PTRACE_POKETEXT, childPid, (void*)rsp, (void*)current_data);

                }

            } else{
                call_counter++;
                data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)newAddr, NULL);
                unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
                ptrace(PTRACE_POKETEXT, childPid, (void*)newAddr, (void*)data_trap);
                isFuncStart = true;

            }
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid, &wait_status, 0);
        }

        ptrace(PTRACE_POKETEXT, childPid, (void*)newAddr, (void*)data);
    }
    /*
    struct user_regs_struct regs;
    int callCounter = 0;
    int wait_status;
    wait(&wait_status);
    long data, got_entry;
    if(dynamic)
    {
    	got_entry = ptrace(PTRACE_PEEKTEXT, childPid, (void*)addr,NULL);
	data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)(got_entry - 6),NULL);
    }
     else
	data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)addr,NULL);
    unsigned long breakpoint_call = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    // Set up the first breakpoint for the function.
   if(dynamic) {
    	ptrace(PTRACE_POKETEXT, childPid, (void*)(got_entry - 6),(void*)breakpoint_call);
	}
     else
	ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_call);
    ptrace(PTRACE_CONT, childPid, NULL, NULL);

    while (WIFSTOPPED(wait_status))
    {
	if(WIFEXITED(wait_status))
		return 0;

        // We reached the call breakpoint.
	if(dynamic) {
        	if(ptrace(PTRACE_POKETEXT, childPid, (void*)(got_entry - 6),(void*)data));
	}
	else
		if(ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)data));
	ptrace(PTRACE_GETREGS, childPid, 0,&regs);
        printf("PRF:: run #%d first parameter is %lld\n",++callCounter, regs.rax);

        // Set up the ret breakpoint, it would stop only when finishing the function now because there is only one breakpoint.
        unsigned long return_address = ptrace(PTRACE_PEEKDATA, childPid, (void *)(regs.rsp), NULL);
        long ret_data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)return_address,NULL);
        unsigned long breakpoint_ret = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
	if(dynamic) {
        	if(ptrace(PTRACE_POKETEXT, childPid, (void*)(got_entry - 6),(void*)breakpoint_ret));
	}
	else
		if(ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_ret));
        ptrace(PTRACE_CONT, childPid, NULL, NULL);

        // Remove the ret breakpoint and set up the call breakpoint.
        wait(&wait_status);
        ptrace(PTRACE_POKETEXT, childPid, (void*)return_address,(void*)ret_data);
        ptrace(PTRACE_GETREGS, childPid, 0,&regs);
        printf("PRF:: run #%d returned with %lld\n",callCounter, regs.rax);
	if(dynamic) {
        	ptrace(PTRACE_POKETEXT, childPid, (void*)(got_entry - 6),(void*)breakpoint_call);
	}
	else {
		ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_call);
	}
        ptrace(PTRACE_CONT, childPid, NULL, NULL);
	dynamic = false;
        wait(&wait_status);
    }
    */

    return 0;
}


pid_t run_target(char* const exe_name)
{
    pid_t childPid = fork();
    if (childPid > 0)
    {
        return childPid;
    }
    else if (childPid == 0)
    {
        ptrace(PTRACE_TRACEME,0, NULL, NULL);
        execl(exe_name, exe_name, NULL);

    }

}