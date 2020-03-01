#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#define BC 0x10

typedef struct bp
{
	uint64_t addr;
	uint64_t backup;
	uint64_t watch;
} bp;


enum user_regs_enum
{
	r15,
    	r14,
    	r13,
    	r12,
    	rbp,
 	rbx,
 	r11,
 	r10,
    	r9,
    	r8,
    	rax,
    	rcx,
    	rdx,
    	rsi,
    	rdi,
    	orig_rax,
    	rip,
    	cs,
    	eflags,
    	rsp,
    	ss,
    	fs_base,
    	gs_base,
    	ds,
    	es,
    	fs,
    	gs,
};

char * regname[27] = {"r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx","rdx","rsi","rdi","orgi_rax","rip","cs","eflags","rsp","ss","fs_base","gc_base","ds","es","fs","gs"};


char * cmd;
pid_t child = -1;
bp * BreakPointList[BC] = {0};

uint64_t readText(uint64_t addr)
{
	return ptrace(PTRACE_PEEKTEXT,child,addr,0);
}

void writeText(uint64_t addr,uint64_t value)
{
	ptrace(PTRACE_POKETEXT,child,addr,value);
}

void singleStep()
{
	ptrace(PTRACE_SINGLESTEP,child,0,0);
}

void cont()
{
	ptrace(PTRACE_CONT,child,0,0);
}	

void getRegs(struct user_regs_struct * regs)
{
	ptrace(PTRACE_GETREGS, child, NULL, regs);
}
void addBp(uint64_t addr,int watch)
{
	int i;
	for(i = 0;i < BC;i++)
	{
		if(BreakPointList[i] == 0)
		{
			bp * BreakPoint = (bp *)malloc(sizeof(bp));
			
			BreakPoint->addr = addr;
			BreakPoint->backup = readText(addr);
			BreakPoint->watch = watch;

			writeText(addr,(BreakPoint->backup&0xffffffffffffff00) | 0xcc);
			BreakPointList[i] = BreakPoint;
			return;
		}
	}
}

/*void mread(char * s,int size)
{
	int i;
	while(i < size)
	{
		read(0,&s[i],1);
		if(s[i] == '\n')
		{
			s[i] = 0;
			return ;
		}
		i++;
	}
}

int cmdParser()
{
	int result = 0;

	printf("CYdbg> ");
	memset(cmd,0,0x100);
	mread(cmd,0xff);
	if(strlen(cmd) != 0)
	{
		printf("%s\n",cmd);
		if(!strcmp(cmd,"r") || !strcmp(cmd,"run"))
		{
			ptrace(PTRACE_CONT,child,0,0);
			result = 1;
		}
		else if(!strcmp(cmd,"c") || !strcmp(cmd,"continue"))
		{
			ptrace(PTRACE_CONT,child,0,0);
			result = 1;
		}
		else if(!strcmp(cmd,"b") || !strcmp(cmd,"break"))
		{
			result = 0;	
		}
		else
		{
			result = 0;
		}
	}
	return result;
}*/

__attribute__((constructor)) void inits()
{
	cmd = (char *)malloc(0x100);
	setbuf(stdin,0);
	setbuf(stdout,0);
}


int findBp(uint64_t addr)
{
	int i;
	for(i = 0;i < BC;i++)
	{
		if(BreakPointList[i]->addr == addr)
		{
			return i;
		}
	}
	return -1;
}

void showReg(struct user_regs_struct regs,int watch)
{
	printf("[*]%5s: 0x%llx\n",regname[watch],*(((long long int *)&regs) + watch));
}

void func(int status)
{
	if((status >> 8) == 0x5)
	{
		struct user_regs_struct regs;
		getRegs(&regs);
		int index = findBp(regs.rip - 1);
		assert(index >= 0);
		
		if(BreakPointList[index]->watch != -1) showReg(regs,BreakPointList[index]->watch);

		writeText(BreakPointList[index]->addr,BreakPointList[index]->backup);
		regs.rip -= 1;
		ptrace(PTRACE_SETREGS, child, NULL, &regs);
		singleStep();
		wait(NULL);
		writeText(BreakPointList[index]->addr,(BreakPointList[index]->backup&0xffffffffffffff00) | 0xcc);
		cont();
	}
}
int main(int argc,char * argv)
{
	int status = -1;
	char filename[] = "./WcyVM";
	char * binsh[] = {"/bin/sh",0};
	struct user_regs_struct regs;

	pid_t pid = fork();
	assert(pid >= 0);
	if(pid == 0)
	{
		ptrace(PTRACE_TRACEME,0,0,0);
		execve("./WcyVM",binsh,NULL);
	}
	else
	{
		child = pid;
		wait(NULL);
		addBp(0x4009C8,rax);
		cont();
		while(status != 0)
		{				
			wait(&status);
			func(status);
		}
	}
	return 0;
}
