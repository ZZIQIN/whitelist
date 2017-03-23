#include"whitelist.h"
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

struct sockaddr_in addr;
#define TEST(IP, TYPE, OUTCOME)\
 do{\
    bzero(&addr,sizeof(addr));\
    addr.sin_family=AF_INET;\
    addr.sin_port=htons(23);\
    addr.sin_addr.s_addr=inet_addr(IP);\
    assert(findWhitelist(&addr,TYPE)==OUTCOME);\
}while(0);

int main() {
    startWhitelist("ip.txt", NULL, 0, 0);
    sleep(2);
    TEST("127.0.0.1",PERM_R,1);
    TEST("127.0.0.1",PERM_W,1);
    TEST("127.0.0.1",PERM_RW,1);
    TEST("192.168.1.1",PERM_RW,1);
    TEST("192.168.1.1",PERM_R,1);
    TEST("192.168.1.1",PERM_W,-1);
    printf("pass!");
    return 0;
}