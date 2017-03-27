#include"whitelist.h"
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>


#define TEST(IP, TYPE, OUTCOME)\
 do{\
    struct sockaddr_in addr;\
    inet_pton(AF_INET, IP, &addr.sin_addr);\
    assert(findWhitelist(&addr,TYPE)==OUTCOME);\
}while(0);

int main() {
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    startWhitelist("ip.txt", NULL, 0, 0);
    sleep(3);
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();startWhitelist("ip.txt", NULL, 0, 0);
    stopWhitelist();
    sleep(3);

//    TEST("192.168.1.1",PERM_RW,1);
//    TEST("127.0.0.1",PERM_RW,1);
//    TEST("123.123.123.123",PERM_R,1);
//    TEST("124.123.123.123",PERM_R,-1);
    printf("pass!");
    return 0;
}
