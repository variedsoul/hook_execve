#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> 

pthread_t main_tid;

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct nlmsghdr *nlh1 = NULL;
struct nlmsghdr *nlh2 = NULL;

struct iovec iov;
struct iovec iov1;
struct iovec iov2;

struct msghdr msg;//hello
struct msghdr msg1;//pass
struct msghdr msg2;//deny
int sock_fd;

#define NMAX 4096
int iput = 0; //环形缓冲区的当前放入位置
int iget = 0; //缓冲区的当前取出位置
int n = 0; //环形缓冲区中的元素总数量
double buffer[NMAX];


//从环形缓冲区中取
int get(char *s)
{
	int pos=0;
	if(iget==NMAX)iget=0;
	if (n>0){
		while(1)
		{
			if(iget==NMAX)iget=0;
			s[pos++]=buffer[iget];
			//zheliyaojiasuo
			n--;
			if(buffer[iget++]==0)break;
		}	
		return pos;
	}
	else {
		printf("Buffer is empty\n");
		return 0;
	}
}
 

//向环形缓冲区中放入
void put(char *s,int size)
{
	int num=0;
	if (n+size<NMAX){
		for(num=0;num<size;num++)
		{
			if(iput==NMAX)iput=0;
			buffer[iput]=s[num];
			iput++;
		}
		//zheliyaojiasuo
		n+=size;
	}else{
		printf("Buffer is full\n");
	}	
}

void *writetofile(void *arg)  
{  
	int fd;
	if((fd=open("/var/log/execvelog.txt", O_WRONLY|O_CREAT|O_APPEND,S_IRWXG|S_IRWXU|S_IRWXO))==-1){
		printf("open file fail\n");
		return ((void *)0);  
	}
	
	char curstring[1024];
	char *start;
	int curlen=0,i=0,j;

	FILE *fstream=NULL;  
	char buff[10] = {0};
	char tmp[100]={0};
    while(1)
    {
    	if(n>0)
    	{
    		curlen=get(curstring);
    		printf("get:%s,%d\n",curstring,curlen);
	    	if(curlen>1024) 
	    	{
	    		printf("get out of buffer\n");
	    		close(fd);
	    		return ((void *)0);  
	    	}
	    	//fwrite(curstring,curlen,1,fd);
	    	strcat(curstring,"\n");

	    	i=0;
	    	while(curstring[i++]==0) curlen--;
	    	start=curstring+i-1;

	    	
	    	char command[100]={0};
	    	memset(tmp, 0, sizeof(tmp));
	    	i=0;
	    	while(start[i]!='\n') {
	    		tmp[i]=start[i];
	    		i++;
	    	}

			sprintf(command,"objdump -d %s | grep -E '[[:space:]](out|in) ' | wc -l",tmp);//sh,objdump,grep,wc ,4 more execve()
			
			//printf("%s\n",command);
			if(NULL==(fstream=popen(command,"r"))){ 
				printf("execute command failed\n"); 
				close(fd); 
				return ((void *)0);  
			}
			if(NULL!=fgets(buff, sizeof(buff), fstream)) { 
				pclose(fstream);
				i=buff[0]-'0';
				if(i==0){
					printf("pass\n");
					
					sendmsg(sock_fd,&msg1,0);
					for(j=curlen-1;j>=0;j--) start[j+6]=start[j];

			    	start[0]='[';
			    	start[1]='p';
			    	start[2]='a';
			    	start[3]='s';
			    	start[4]='s';
			    	start[5]=']';
				}else
				{
					printf("deny\n");
					sendmsg(sock_fd,&msg2,0);
					for(j=curlen-1;j>=0;j--) start[j+6]=start[j];

			    	start[0]='[';
			    	start[1]='d';
			    	start[2]='e';
			    	start[3]='n';
			    	start[4]='y';
			    	start[5]=']';
				}    	
		    	write(fd, start, curlen+6);
		    }else{
		    	close(fd); 
		    	pclose(fstream);
				return ((void *)0);  
		    }
	    }
    }
    close(fd);
    return ((void *)0);  
} 

void init_msg()
{
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), "Hello");

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	nlh1 = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh1, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh1->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh1->nlmsg_pid = getpid();
	nlh1->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh1), "pass");

	iov1.iov_base = (void *)nlh1;
	iov1.iov_len = nlh1->nlmsg_len;
	msg1.msg_name = (void *)&dest_addr;
	msg1.msg_namelen = sizeof(dest_addr);
	msg1.msg_iov = &iov1;
	msg1.msg_iovlen = 1;

	nlh2 = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh2, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh2->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh2->nlmsg_pid = getpid();
	nlh2->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh2), "deny");

	iov2.iov_base = (void *)nlh2;
	iov2.iov_len = nlh2->nlmsg_len;
	msg2.msg_name = (void *)&dest_addr;
	msg2.msg_namelen = sizeof(dest_addr);
	msg2.msg_iov = &iov2;
	msg2.msg_iovlen = 1;
}

int main()
{
	char *msgchar;
	sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(sock_fd<0)
	return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	init_msg();
	/*init_msg(nlh,&iov,&msg,"Hello");
	init_msg(nlh1,&iov1,&msg1,"pass");
	init_msg(nlh2,&iov2,&msg2,"deny");*/

	//printf("Sending Hello to kernel\n");
	sendmsg(sock_fd,&msg,0);

	int err;  
    err = pthread_create(&main_tid, NULL, writetofile, NULL); 
    if(err != 0){  
        printf("create thread error: %s/n",strerror(err));  
        return 0;  
    }  

	//recvmsg from kernel
	while(1){
		recvmsg(sock_fd, &msg, 0);
		msgchar=(char *)NLMSG_DATA(nlh);

		printf("Received : %s,%d\n", msgchar,nlh->nlmsg_len);
		put(msgchar,strlen(msgchar)+1);
	}	
	close(sock_fd);
}