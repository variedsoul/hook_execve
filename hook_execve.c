#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/kthread.h>

MODULE_LICENSE("GPL");
static struct jprobe jp;
struct task_struct *my_thread;
#define NETLINK_USER 31

struct sock *nl_sk = NULL;
int user_pid;
int need_send_msg=0;//for thread's use,now it's abandoned.
char send_message[0x30];
int should_stop=0;
spinlock_t spinlock;
static void send_msg(char* msg);
int count=0;//about when to send msg
int start_work=0;//user start?

asmlinkage int new_execve(const char __user *name,
	const char __user *const __user *argv,
	const char __user *const __user *envp
	/*,struct pt_regs *regs*/)
{
	if(!start_work) count=0;
	if(user_pid!=0) start_work=1;

	if(start_work)
	{
		if(count==5)count=0;
		count++;
		//printk("[%s] from pid:%d,parent pid:%d,parent tgid:%d,parent's parent pid:%d\n", name,current->pid,current->parent->pid,current->parent->tgid,current->parent->parent->pid);
		spin_lock(&spinlock);
		need_send_msg=1;
		spin_unlock(&spinlock);
		if(user_pid!=0 && current->parent->tgid!=user_pid && current->parent->parent->tgid!=user_pid)
			send_msg(name);
		//if(count==1)send_msg(name);//1 send, 2,3,4,5 not send
	}
	

	jprobe_return();
	return 0;
}

//for syn communication with user,this thread is abandoned.
int my_thread_main(void* data)
{
	char *msg="recv from kernel";
	printk("thread init ok\n");

	while(!kthread_should_stop() && !should_stop){
	       //printk("!kthread_should_stop()\n");
		if(need_send_msg)
		{
			send_msg(msg);
			spin_lock(&spinlock);
			need_send_msg=0;
			spin_unlock(&spinlock);
		}

	        //set_current_state(TASK_INTERRUPTIBLE);
	        //schedule();
	}
	printk("thread stop ok\n");
	return 0;
}

static void send_msg(char* msg)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int res;
	int msg_size;
	msg_size=strlen(msg)+1;
	skb_out = nlmsg_new(msg_size,0);
	if(!skb_out)
	{
	    printk(KERN_ERR "Failed to allocate new skb\n");
	    return;
	} 

	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh),msg,msg_size);

	//printk("in send\n");
	res=nlmsg_unicast(nl_sk,skb_out,user_pid);
	printk(KERN_INFO "tried to send to user.\n");
	if(res<0){
	    printk(KERN_INFO "Error while sending back to user\n");
	    should_stop=1;
	    start_work=0;
	}
}

static void hello_nl_recv_msg(struct sk_buff *skb) 
{
	struct nlmsghdr *nlh;
	int msg_size;
	char *msg="Hello from kernel";

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	msg_size=strlen(msg);

	nlh=(struct nlmsghdr*)skb->data;
	printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
	user_pid = nlh->nlmsg_pid; /*pid of sending process */
	printk("netlink_user_pid %d\n",nlh->nlmsg_pid);

	//wake_up_process(my_thread);

	/*if(!need_send_msg)
		send_msg(send_message);
	else
		send_msg("ERROR");*/
}

static int hello_init(void) {

	printk("Entering: %s\n",__FUNCTION__);
	/*This is for 3.6 kernels and above.*/
	struct netlink_kernel_cfg cfg = {
	    .input = hello_nl_recv_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	/* for < 3.6 kernels
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg,NULL,THIS_MODULE);
	*/
	if(!nl_sk)
	{
	    printk(KERN_ALERT "Error creating socket.\n");
	    return -1;
	}
	my_thread=kthread_create_on_node(my_thread_main,NULL,0,"my_thread");
	if(my_thread==NULL)
    {
        printk("new thread error\n");
        return -2;
    }
	return 0;
}

static void hello_exit(void)
{
	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);
}

static int __init syscall_hook_init(void)
{
	int ret = -1;
	if(hello_init()<0){
		printk("hello_init failed, returned %d\n", ret);
		return -1;
	}
	printk("syscall_hook module is starting..!\n");
	jp.entry = (kprobe_opcode_t *)new_execve;
	jp.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sys_execve");
	if (!jp.kp.addr) {
		printk("can't find the address of sys_execve..\n");
		return -1;
	}
	if ((ret = register_jprobe(&jp)) < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	spin_lock_init(&spinlock);
	return 0;
}

static void __exit syscall_hook_exit(void)
{
	printk("syscall_hook module is finishing....\n");
	if(my_thread)
        kthread_stop(my_thread);
	hello_exit();
	unregister_jprobe(&jp);

}

module_init(syscall_hook_init);
module_exit(syscall_hook_exit);