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

typedef struct bp
{
	uint64_t addr;
	uint64_t backup;
} bp;

char * cmd;
pid_t child = -1;
bp * BreakPointList[0x10] = {0};

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

void addBp(uint64_t addr)
{
	int i;
	for(i = 0;i < 0x10;i++)
	{
		if(BreakPointList[i] == 0)
		{
			bp * BreakPoint = (bp *)malloc(sizeof(bp));
			BreakPoint->addr = addr;
			BreakPoint->backup = readText(addr);
			printf("%x:%llx\n",addr,BreakPoint->backup);
			writeText(addr,(BreakPoint->backup&0xffffffffffffff00) | 0xcc);
			printf("%llx\n",readText(addr));
			BreakPointList[i] = BreakPoint;
			return;
		}
	}
}

void mread(char * s,int size)
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
}

__attribute__((constructor)) void inits()
{
	cmd = (char *)malloc(0x100);
	setbuf(stdin,0);
	setbuf(stdout,0);
}

void func()
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, child, NULL, &regs);
	printf("rax:%x\n", regs.rax);
	//printf("bladdr:%llx :%llx\n",BreakPointList[0]->addr,BreakPointList[0]->backup);
	writeText(BreakPointList[0]->addr,BreakPointList[0]->backup);
	//printf("addr:%llx :%llx\n", regs.rip,readText(regs.rip));
	regs.rip -= 1;
	//printf("addr:%llx :%llx\n", regs.rip,readText(regs.rip));
	ptrace(PTRACE_SETREGS, child, NULL, &regs);
	singleStep();//error
	wait(NULL);
	writeText(BreakPointList[0]->addr,(BreakPointList[0]->backup&0xffffffffffffff00) | 0xcc);
	cont();
}
int main(int argc,char * argv)
{
	int status = -1;
	char filename[] = "./WcyVM";
	char * binsh[] = {"/bin/sh",0};
	struct user_regs_struct regs;
	
	int fd = open(filename,O_RDWR);

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
		addBp(0x4009C8);
		cont();
		while(status != 0)
		{
			//ptrace(PTRACE_GETREGS,pid,NULL,&regs);
			//printf("rip:%llx\n",regs.rip);
			//ptrace(PTRACE_POKEDATA,pid,0x601030,0x666c6167666c6167);
			//if(cmdParser())
			//{				
			wait(&status);
			printf("%d\n",status);
			func();
			 //wait(&status);
			 //                        printf("%d\n",status);
			//}//
		}
	}
	return 0;
}
