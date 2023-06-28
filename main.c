

#include <stdio.h>
#include "find_symbol.c"
#include <sys/ptrace.h>
#include <user.h>

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

    pid_t childPid = run_target(argv[2]);
    struct user_regs_struct regs;
    int callCounter = 0;
    int wait_status;
    wait(&wait_status);
    long data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)addr,NULL);
    unsigned long breakpoint_call = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    // Set up the first breakpoint for the function.
    ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_call);
    ptrace(PTRACE_CONT, childPid, NULL, NULL);

    while (WIFSTOPPED(wait_statuss))
    {
        // TODO: ADD CHECK IF TERMINATED.


        
        // We reached the call breakpoint.
        ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)data);
        ptrace(PTRACE_GETREGS, childPid, 0,&regs);
        printf("PRF:: run #%d first parameter is %llx\n",++callCounter, regs.rax);

        // Set up the ret breakpoint, it would stop only when finishing the function now because there is only one breakpoint.
        unsigned long return_address = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp), NULL);
        long ret_data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)return_address,NULL);
        unsigned long breakpoint_ret = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_ret);
        ptrace(PTRACE_CONT, childPid, NULL, NULL);

        // Remove the ret breakpoint and set up the call breakpoint.
        wait(&wait_status);
        ptrace(PTRACE_POKETEXT, childPid, (void*)return_address,(void*)ret_data);
        ptrace(PTRACE_GETREGS, childPid, 0,&regs);
        printf("PRF:: run #%d returned with %llx\n",callCounter, regs.rax);
        ptrace(PTRACE_POKETEXT, childPid, (void*)addr,(void*)breakpoint_call);
        ptrace(PTRACE_CONT, childPid, NULL, NULL);
    }

    
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
        if (ptrace(PTRACE_TRACEME,0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        execl(exe_name, exe_name, NULL);
        
    }else
    {
        perror("fork");
        exit(1);
    }
    
}