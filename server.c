#include"whitelist.h"
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
	
int main(int argc, char **argv)  
{  
    startWhitelist("ip.txt","log.txt",0,0);
    int listenfd, connfd,n;  

    struct sockaddr_in servaddr;  
    char buff[1000];  
    time_t ticks;  
    if(( listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )  
    {  
        printf("socket error! \n");  
        exit(1);  
    }  
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(8888);  
      

    if(bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0 )  
    {  
        printf("bind error! \n");  
        exit(1);  
    }  
      

    if( listen(listenfd, 10) < 0 )  
    {  
        printf( "listen error! \n" );  
        exit(1);  
    }  
      

    for( ; ; )  
    {  
        if((connfd = accept(listenfd,(struct sockaddr *)NULL,NULL))<0)  
        {  
            printf("accept error! \n");  
            exit(1);  
        }  
        if(findWhitelistByFd(connfd,PERM_R)!=1){
            close(connfd);
            continue;
	    }
        ticks = time(NULL);  
        snprintf(buff, sizeof(buff), "%24s\r\n", ctime(&ticks));  
        if((n = write(connfd,buff,strlen(buff)))<0)  
        {  
            printf("write error! \n");  
            exit(1);              
        }  
          
        if(close(connfd)<0)  
        {  
            printf("accept error! \n");  
            exit(1);              
        }
	    stopWhitelist();
        stopWhitelist();
        stopWhitelist();
	    startWhitelist("ip.txt","log.txt",0,0);
        startWhitelist("ip.txt","log.txt",0,0);
        startWhitelist("ip.txt","log.txt",0,0);
    }  
    return 0;
}

