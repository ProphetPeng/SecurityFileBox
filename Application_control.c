#include<sys/stat.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/netlink.h>
#include<sys/socket.h>
#include<fcntl.h>
#include<asm/types.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<signal.h>
#include<pwd.h>
#include<errno.h>
#include <linux/sched.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#define NetLink_TEST 29
#define MAX_PAYLOAD 1024

#   define COL(x)  "\033[;" #x "m"
#   define RED     COL(31)
#   define GREEN   COL(32)
#   define YELLOW  COL(33)
#   define BLUE    COL(34)
#   define MAGENTA COL(35)
#   define CYAN    COL(36)
#   define WHITE   COL(0)
#   define GRAY    "\033[0m"

//command  list
#define SEND_PASSWORD 'A'
#define COMFIRM_PASSWORD 'B'
#define ERROR_PASSWORD 'C'
#define CHANGE_FILEPATH 'D'
#define LOG_THREAD 'F'
#define LOG_SEAND 'G'

struct control_command
{
   	
	struct nlmsghdr *nlh;
	char *command_contact;

};

int sock_fd;
struct msghdr msg;
struct msghdr rec_msg;  // receive message  
struct nlmsghdr *nlh = NULL;
struct sockaddr_nl src_addr, dest_addr;
struct iovec iov;
struct iovec rec_iov;  // receive iovec
struct control_command cc;


FILE *logfile;
FILE *passfile;
char *composecommand(char *contact,char commandnum);
void sendmsgtokernel(unsigned int pid,char *contact);
void killdeal_func();

void log_thread(void)
{
	printf("\t LOG: log thread start!!\n");
	char logpath[32];
	strcpy(logpath, "./log.txt");
	
	
	while(1)
	{
		if(recvmsg(sock_fd, &msg, 0)!=-1)
		{
			nlh = (struct nlmsghdr *) msg.msg_iov->iov_base;
            char *feedback  = NLMSG_DATA(nlh);
            if (feedback[0]==LOG_SEAND) {
				time_t t;
   				time(&t);
				logfile = fopen(logpath, "a");
				char buff[256];
				printf(buff,"time: %s \n", ctime(&t));
				sprintf(buff,"time: %s \n", ctime(&t));
				fputs(buff,logfile);
                fputs((feedback+1),logfile);
				fputc('\n',logfile);
				fclose(logfile);
            }
		}
	}

}

int main(int argc, char *argv[])
{
	//start  information
	printf("\t  Welcome to Security Box!	Beta 1.0 \n");
	printf("--------------------------------------------\n");

	//terminate signal
	signal(SIGTERM, killdeal_func);	
	
	//establish socket connect
	sock_fd = socket(PF_NETLINK,SOCK_RAW,NetLink_TEST);
	printf("socket connect start!\n");
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    
    char password_a[256];
	passfile = fopen("p.txt", "r");
    fgets(password_a, 256, passfile);
    
    //printf("%s \n",password_a);
    
    while(1) {
    	char password_i[10],password_t[10];
		printf("please enter your PassWord: \n");
		scanf("%s",&password_t);
		strncpy(password_i,password_t,9);
		password_i[9]='\0';
        int passlenth=strlen(password_i);
         //printf("%d \n",passlenth);
        password_a[ passlenth]='\0';
        //printf("%s \n",password_b);
	    if(strcmp(password_t,password_a))
        {
           printf("error password! \n");
            continue;
        }

		sendmsgtokernel(getpid(),composecommand("123456",SEND_PASSWORD));
		if(recvmsg(sock_fd, &msg, 0)!=-1)
		{
			nlh = (struct nlmsghdr *) msg.msg_iov->iov_base;
            char *feedback  = NLMSG_DATA(nlh);
            if (feedback[0]=='B') {
            	printf("\t log in success ! \n");
                break;
            }
            else if (feedback[0]=='C')
            	printf("\t error password ! \n");
		}
	}

	pthread_t log_threa_id;
	int ret;
	ret=pthread_create(&log_threa_id,NULL,(void *) log_thread,NULL);
	
    while(1) {

    	printf("select one mode :\n");
		printf("1 to modify security file path.\n");
		printf("2 to eidt file. \n");
		printf("3 to quit program. \n");

        char mode[10];
        scanf("%s",&mode);
        if (strcmp(mode,"1")==0) {
        	printf("input the file path :\n");
            char FilePath[256];
            scanf("%s", &FilePath);
            sendmsgtokernel(getpid(),composecommand(FilePath,CHANGE_FILEPATH));
            printf("modify success!\n"); 
        }
        else if (strcmp(mode,"2")==0) {
            printf("input the command you want to execute:\n");
			printf("(like \"ls\" ps:input \"quit\" to quit)\n");
            char command[256];
            while(1) {
                int i=0;
                while((command[i]=getchar())!='\n' && i<255) {
                	i++;
                }
            	command[i]='\0';
                if(strcmp(command,"quit")==0)
                	break;
                else {
                    system(command);
                }
            }
        }
        else if (strcmp(mode,"3")==0)
            break;
        else
            printf("error mode !\n");
    }
	


	close(sock_fd);
	free(nlh);
	fclose(logfile);
	return 0;
}


void sendmsgtokernel(unsigned int pid,char *contact)
{
	
	memset(&msg, 0, sizeof(msg));
	memset(&rec_msg, 0, sizeof(rec_msg));
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = pid;
	src_addr.nl_groups = 0;
	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
	memset(&dest_addr,0,sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;
	nlh->nlmsg_len=NLMSG_SPACE(MAX_PAYLOAD);
	//nlh->nlmsg_len=NLMSG_ALIGN(15);
	nlh->nlmsg_pid=pid;
	nlh->nlmsg_flags=0;
	
	//char *contact=(char*)malloc(20*sizeof(char));
	//strcpy(contact,"hellow kernel!");
	//void *buffer;
	//buffer=malloc(15*sizeof(char));
	//memset(buffer,0,15);
	//strncpy((char *)buffer,"hellow kernel!",15);b
	
        //char * str = "hello kernel!";
	memcpy(NLMSG_DATA(nlh), (char *) contact, strlen(contact)+1);
	//printf("%s \n",NLMSG_DATA(nlh));
	
	//cc.nlh=nlh;
	//cc.command_contact=contact;
	iov.iov_base = (void *)nlh;
	iov.iov_len = 	nlh->nlmsg_len;
	//printf("%s \n",contact);
	//msg name
	msg.msg_name = (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(sock_fd, &msg, 0);
}

void killdeal_func()
{
	printf("END!\n");
	close(sock_fd);
	if (logfile != NULL)
	{
		fclose(logfile);
	}
	if (nlh != NULL)
	{
		free(nlh);
	}
	exit(0);
}char *composecommand(char *contact,char commandnum)
{
	int c_len=strlen(contact);
	char *cc=malloc((c_len+2)*sizeof(char));
	cc[0]=commandnum;
	int i=1; 
	while(i<=c_len+1)
	{
		cc[i]=contact[i-1];
		i++;
	}
	cc[i+1]='\0';
	//printf("%s \n",cc);
	return cc;	
}

