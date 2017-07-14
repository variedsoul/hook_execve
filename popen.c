#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> 

int main(){
	FILE *fstream=NULL;  
	char buff[10] = {0};

	char command[0x100]={0};
	//sprintf(command,"objdump -d %s | grep out | wc -l",start);
	sprintf(command,"ls|wc -l");
	printf("%s\n",command);
	if(NULL==(fstream=popen(command,"r"))){ 
		printf("execute command failed\n"); 
		return 0;  
	}
	if(NULL!=fgets(buff, sizeof(buff), fstream)) { 
		pclose(fstream);
		int i=buff[0]-'0';
		if(i==0){
			printf("pass\n");
			
		}else
		{
			printf("deny\n");
			
		}    	

		
	}else{
		pclose(fstream);
		return 0;  
	}
}
