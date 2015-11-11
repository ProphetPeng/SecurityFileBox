#include <Linux/module.h>
#include <Linux/kernel.h>
#include <Linux/init.h>
#include <Linux/syscalls.h>
#include <Linux/file.h>
#include <Linux/fs.h>
#include <Linux/string.h>
#include <Linux/mm.h>
#include <Linux/sched.h>
#include <Linux/unistd.h>
#include <net/sock.h>
#include <net/netlink>

#define TASK_COMM_LEN 16  // 进程对应的可执行文件名长度
#define SecurityPath "/home/pp"   // security file path
#define MAX_LENGTH 256

module_init(AccessControl_init);
module_exit(AccessControl_exit);
MODULE_LICENSE("GPL");

void ** sys_call_table;  // 指向系统调用入口表的地址
asmlinkage long(* orig_open)(const char *pathname, int flags, mode_t mode); //用于保存原来的open系统调用处理函数地址
static u32 pid = 0; // 安全文件保险箱应用程序的进程标识符

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
	unsigned int orig_cr0 = clear_and_return_cr0(); //清除控制寄存器CR0的写保护检查控制位，并保存CR0寄存器的原始值
    sys_call_table = get_sys_call_table(); //获取系统调用入口地址表的首地址
    printk("Info: sys_call_table found at %lx\n", (unsigned long)sys_call_table); //输出系统调用入口地址表的首地址
    orig_open = sys_call_table[__NR_open]; /*保存open系统调用的原始处理函数入口地址，
                          __NR_open为open的系统调用号，该号对应open系统调用处理函数在系统调用入口地址表的位置*/
    sys_call_table[__NR_open] = hacked_open; //重载open系统调用处理函数的入口地址
    asm volatile("movl % % eax, % % cr0" : : "a"(orig_cr0)); //恢复控制寄存器CR0的值，即恢复写保护检查控制位
    return 0;
}

void * get_sys_call(void) //获取系统调用处理函数的入口地址表
{
	unsigned char idtr[6];
	unsigned long base;    //存储中断向量表的首地址
	struct idt_descriptor desc;
    asm ("sidt % 0" : " =m" (idtr)); //取出中断向量寄存器的内容
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

// module exit
static int __exit AccessControl_exit(void)
{
	unsigned init orig_cr0 = clear_and_return_cr0(); //清除控制寄存器CR0的写保护检查控制位，并保存CR0寄存器的原始值
    sys_call_table[__NR_open] = orig_open;  //恢复原始open系统调用处理函数
    asm volatile("movl % % eax, % % cr0" : : "a"(orig_cr0)); //恢复控制寄存器CR0的值，即恢复写保护检查控制位
}

unsigned int clear_and_return_cr0(void) // 清除控制寄存器CR0的写保护检查控制位
{
	unsigned int cr0 = 0;
    unsigned int ret;     // 保存CR0寄存器的原始值
    asm volatile("movl % % cr0, % % eax" : " = a"(cr0)); //将CR0寄存器的原始值读入到变量cr0中
    ret = cr0;
    cr0 &= 0xfffeffff; //修改CR0的值，将其第16位（即写保护检查控制位）置0
    asm volatile("movl % % eax, % % cr0" : : "a"(cr0)); //将清除写保护检查控制位后的值回写到CR0寄存器
    return ret;
}

//新重载的open系统调用处理函数
asmlinkage long hacked_open(const char *pathname, int flags, mode_t mode)
{
	long ret;                          // 记录原open系统调用处理函数的返回值
	char commandname[TASK_COMM_LEN];   // 程序名缓冲区
	char fullname[256];                // 所打开文件的全路径名缓冲区
    memset(fullname, 0, 256);          // 初始化所打开文件的全路径名缓冲区
    get_fullname(pathname, fullname);  // 获得所打开文件的全路径名
    if(strcmp(fullname, SecurityPath) != 0)
    {
    	ret = orig_open(pathname, flags, mode); 
    	return ret;
    }
    else
    {
    	printk("You have no access to open it!");
    }

}

void get_fullname(const char *pathname, char *fullname)
{
	struct dentry * tmp_dentry = current->fs->pwd;   //获取该进程的当前目录
	char tmp_path[MAX_LENGTH];    //保存路径名的临时缓冲区
	char local_path[MAX_LENGTH];  //保存路径名的临时缓冲区
	memset(tmp_path, 0, MAX_LENGTH);
	memset(local_path, 0, MAX_LENGTH); 
	if (*pathname == "/") {
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
	return;
}