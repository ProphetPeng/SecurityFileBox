#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <net/netlink.h>

#define SEND_PASSWORD 'A'
#define COMFIRM_PASSWORD 'B'
#define ERROR_PASSWORD 'C'
#define CHANGE_FILEPATH 'D'
#define COMFIRM_CHANGE_PASSWORD 'E'
#define LOG_THREAD 'F'
#define LOG_SEAND 'G'

#define Netlink_TEST 29   // 日志应用程序和内核模块预定用于传递信息的Netlink协议编号  
#define MAX_LENGTH 256

void ** sys_call_table;  // 指向系统调用入口表的地址
static u32 pid = 0; // 安全文件保险箱应用程序的进程标识符
static struct sock *nl_sk = NULL; // 用于Netlink通信的套接字
static char *password_r="123456";
static char *SecurityPath="/home/zsy/demo"; // security file path
static  struct nlmsghdr *nlh; //Netlink消息头指针
void netlink_init(void);
void netlink_release(void);
void nl_data_ready(struct sk_buff *__skb); 
int netlink_sendmsg(const void *buffer, int pid) ;
unsigned int clear_and_return_cr0(void);
void * get_sys_call(void);
void * get_sys_call_table(void);

void get_fullname(const char *pathname, char *fullname);
void commandoper(char * cc);
char *composecommand(char *contact,char commandnum);

asmlinkage long hacked_open(const char *pathname, int flags, mode_t mode);
asmlinkage long(* orig_open)(const char *pathname, int flags, mode_t mode); 


// interupt descriptor
struct idt_descriptor
{
	/* data */
	unsigned short off_low;    
	unsigned short sel;
	unsigned char none, flags;
	unsigned short off_hign;
};

// module initial
static int __init AccessControl_init(void)
{
	//printk(KERN_DEBUG"\"%s(pid%d)\" open scnum device!\n",current->comm,current->pid);
	//current->fs->root;
	unsigned int orig_cr0 = clear_and_return_cr0(); //清除控制寄存器CR0的写保护检查控制位，并保存CR0寄存器的原始值
    sys_call_table = get_sys_call_table(); //获取系统调用入口地址表的首地址
    printk("<0>""Info: sys_call_table found at %lx\n", (unsigned long)sys_call_table); //输出系统调用入口地址表的首地址
    orig_open = sys_call_table[__NR_open]; /*保存open系统调用的原始处理函数入口地址，__NR_open为open的系统调用号，该号对应open系统调用处理函数在系统调用入口地址表的位置*/
    sys_call_table[__NR_open] = hacked_open; //重载open系统调用处理函数的入口地址
    asm volatile("movl %% eax, %% cr0" : : "a"(orig_cr0)); //恢复控制寄存器CR0的值，即恢复写保护检查控制位
    netlink_init();
    return 0;
}

unsigned int clear_and_return_cr0(void) // 清除控制寄存器CR0的写保护检查控制位
{
    unsigned int cr0 = 0;
    unsigned int ret;     // 保存CR0寄存器的原始值
    asm volatile("movl %% cr0, %% eax" : " = a"(cr0)); //将CR0寄存器的原始值读入到变量cr0中
    ret = cr0;
    cr0 &= 0xfffeffff; //修改CR0的值，将其第16位（即写保护检查控制位）置0
    asm volatile("movl %% eax, %% cr0" : : "a"(cr0)); //将清除写保护检查控制位后的值回写到CR0寄存器
    return ret;
}

void * get_sys_call(void) //获取系统调用处理函数的入口地址表
{
	unsigned char idtr[6];
	unsigned long base;    //存储中断向量表的首地址
	struct idt_descriptor desc;
    asm ("sidt %0" : " =m" (idtr)); //取出中断向量寄存器的内容
    base = * ((unsigned long *) &idtr[2]); //获得中断向量表的首地址
    memcpy(&desc, (void *)(base + (0x80 * 8)), sizeof(desc)); /*获得实现系统调用的中断（对应中断号为0x80）的信息
                                        由于每一个中断的信息结构占8字节，所以该中断的信息在中断向量表中的偏移地址位
                                        （0x80 * 8）*/
    return ((void *)((desc.off_hign << 16) + desc.off_low)); //将高地址左移16位
}

void * get_sys_call_table(void)
{
	void * system_call = get_sys_call(); //获取系统调用处理函数的地址
	unsigned char *p; //临时性指针变量
    unsigned long sct; //缓存系统调用入口地址表的首地址指针
    int count = 0;
    p = (unsigned char *) system_call;
    /* 下面的循环在系统调用处理函数的代码段中搜索call指令的位置，call指令的指令码为"0xff1485" */
    while(!((*p == 0xff) && (*(p+1) == 0x14) &&(*(p+2) == 0x85)))
    {
    	p++;
        if (count ++> 500) {
        	count = -1; //设置不成功标志
        	break;
        }
    }
    if (count != -1) {
    	p += 3;  //跳过指令码，获取第一个操作数，该操作数即为系统调用入口地址表的首地址
        sct = *((unsigned long *) p);      
    }
    else
    	sct = 0; //没有成功获得系统调用入口地址表的首地址
    return ((void *) sct);
}

void netlink_init(void)
{
    nl_sk = netlink_kernel_create(&init_net, Netlink_TEST, 0, nl_data_ready, NULL, THIS_MODULE);
    if (!nl_sk) {
        printk(KERN_ERR "netlink: Cannot create netlink socket.\n");
        if (nl_sk != NULL)
            sock_release(nl_sk->sk_socket);
    }
    else
        printk("netlink: create socket ok.\n");
}

void nl_data_ready(struct sk_buff *__skb) // 在基于Netlink的Socket接口有数据到达时，linux内核自动会调用此函数
{
    printk(" NetLink:nl_data_ready Start\n");
    struct sk_buff *skb;  //消息报文缓冲区指针
	skb=skb_get(__skb);
	if(skb->len>= sizeof(struct nlmsghdr))
	{
		nlh=(struct nlmsghdr*)skb->data;
		//pid = nlh->nlmsg_pid;
		commandoper(NLMSG_DATA(nlh));
		printk(" Kernel Recieve : %s \n", (char *)NLMSG_DATA(nlh));
		printk("NetLink:netlink: pid is %d.\n", pid);
	}
 	printk(" NetLink:nl_data_ready Start end\n");
	
	return;
}

// module exit
static int __exit AccessControl_exit(void)
{
	unsigned int orig_cr0 = clear_and_return_cr0(); //清除控制寄存器CR0的写保护检查控制位，并保存CR0寄存器的原始值
    sys_call_table[__NR_open] = orig_open;  //恢复原始open系统调用处理函数
    asm volatile("movl %% eax, %% cr0" : : "a"(orig_cr0)); //恢复控制寄存器CR0的值，即恢复写保护检查控制位
    netlink_release();
}
//释放netlink资源
void netlink_release(void)
{
    if (nl_sk != NULL)
        sock_release(nl_sk->sk_socket);
}

//发送netlink消息message  
int netlink_sendmsg(const void *buffer,int pid)  
{
	printk(KERN_ERR "kernel sendmesg!\n");
    struct sk_buff *skb;
    struct nlmsghdr *nlh;            //Netlink的消息头指针
    int len = NLMSG_SPACE(1200);     //发送消息的最大长度为1200，len为考虑消息头后的长度
    if((!buffer) || (!nl_sk) || (pid == 0))  //如果应用程序没有告诉其进程标识符，则不发送消息  
        {
		
		printk(" sendmesg error: %s %d %d\n",buffer,nl_sk,pid);
		return 1;
	}

    skb = alloc_skb(len, GFP_ATOMIC);   //分配一个新的sk_buffer
    if (!skb){                          // 分配不成功
        printk(KERN_ERR "net_link: allocat_skb failed.\n");
        return 1;
    }
    
	
	nlh = nlmsg_put(skb,0,0,0,1200,0);   //nlh connect skb
    NETLINK_CB(skb).pid = 0;      //allocte from kernel
    //下面必须手动设置字符串结束标志\0，否则用户程序可能出现接收乱码
    memcpy(NLMSG_DATA(nlh), buffer, strlen((char*)buffer)+1);
    //使用netlink单播函数发送消息
    if( netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT) < 0){
    //如果发送失败，则打印警告并退出函数
        printk(KERN_ERR "net_link: can not unicast skb \n");
        return 1;
    }
    return 0;
}
void commandoper(char * cc)
{	
	int c_len=strlen(cc);
	if(cc[0]==SEND_PASSWORD)
	{	
		char *password_t = cc+1;
		printk("%s \n",password_t);
		if(strcmp(password_t,password_r)==0)
		{
			pid = nlh->nlmsg_pid;
			printk("be comfirmed!!! \n");
			netlink_sendmsg(composecommand("success!",COMFIRM_PASSWORD),pid);
		}
		else
		{
			netlink_sendmsg(composecommand("failed!",ERROR_PASSWORD), nlh->nlmsg_pid);
		}
	}
    else if(cc[0]==CHANGE_FILEPATH)
    {
    	SecurityPath = cc+1;
        printk("Security file path : %s \n", SecurityPath);
    }
}

void get_fullname(const char *pathname, char *fullname)
{
    
    struct dentry *tmp_dentry = current->fs->pwd.dentry;   //获取该进程的当前目录
    char tmp_path[MAX_LENGTH];    //保存路径名的临时缓冲区
    char local_path[MAX_LENGTH];  //保存路径名的临时缓冲区
    memset(tmp_path, 0, MAX_LENGTH);
    memset(local_path, 0, MAX_LENGTH); 
    if (*pathname == '/') {
        strcpy(fullname, pathname);
        return;
    }

    //pathname为相对路径名，首先获得当前所在目录的路径
    while (tmp_dentry != NULL) {
        if (!strcmp(tmp_dentry->d_iname, "/"))
            break;
        strcpy(tmp_path, "/");
        strcat(tmp_path, tmp_dentry->d_iname);
        strcat(tmp_path, local_path);
        strcpy(local_path, tmp_path);
        tmp_dentry = tmp_dentry->d_parent;
    }
    strcpy(fullname, local_path);
    strcat(fullname, "/");
    strcat(fullname, pathname);
    //printk("<1>""%s is input\n",pathname);
    //printk("<1>""%s is output\n",fullname);
    return;
}

//新重载的open系统调用处理函数
asmlinkage long hacked_open(const char *pathname, int flags, mode_t mode)
{
	//printk("%d :::%d \n",current->pid,current->real_parent->pid);
	long ret;                          // 记录原open系统调用处理函数的返回值
	char commandname[TASK_COMM_LEN];   // 程序名缓冲区
	char fullname[256];                // 所打开文件的全路径名缓冲区
    memset(fullname, 0, 256);          // 初始化所打开文件的全路径名缓冲区
    get_fullname(pathname, fullname);  // 获得所打开文件的全路径名
    char tmp_path[256];
    int len = strlen(SecurityPath);
	while(len<strlen(fullname)&&fullname[len]!='/')
	{
		len++;
	}
    memcpy(tmp_path,fullname, len);
	tmp_path[len]='\0';
    if(strcmp(tmp_path, SecurityPath) != 0) {
    	ret = orig_open(pathname, flags, mode); 
    	return ret;
    }
    else {
	    if(current->real_parent->pid == pid) {
			if(pid!=0)
			{
				int spid=current->pid;
				int ppid=current->real_parent->pid;
				char logbuff[256];
				sprintf(logbuff,"pid:%d ppid:%d comm:%s access this file!\n",spid,ppid,current->comm);
				printk("pid:%d ppid:%d have access this file!  %s \n ",spid,ppid,current->comm);
				netlink_sendmsg(composecommand(logbuff,LOG_SEAND), pid);
			} 
        		ret = orig_open(pathname, flags, mode);  
    	    	return ret;
        }
        else{
			if(pid!=0)
			{
				int spid=current->pid;
				int ppid=current->real_parent->pid;
				char logbuff[256];
				sprintf(logbuff,"pid:%d ppid:%d comm:%s be rejected!\n",spid,ppid,current->comm);
				printk("pid:%d ppid:%d comm:%s be rejected!\n",spid,ppid,current->comm);
				netlink_sendmsg(composecommand(logbuff,LOG_SEAND), pid);
			} 
        	printk("You have no access to open it");
        }
	
    }

}
char *composecommand(char *contact,char commandnum)
{
	int c_len=strlen(contact);
	char *cc=kmalloc((c_len+2)*sizeof(char),0);
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
module_init(AccessControl_init);
module_exit(AccessControl_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("pengpeng <prophet_peng@163.com>");
