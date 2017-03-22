#ifndef __WHITELIST_H__
#define __WHITELIST_H__

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/******************************
      Extern declarations
******************************/


#define WHITELIST_ON        1
#define WHITELIST_OFF        0

#define CONN_PERM_CHECK        0
#define WRITE_PERM_CHECK    1

#define PERM_NONE     0
#define PERM_R        1
#define PERM_W        2
#define PERM_RW       3
extern int findWhitelist(int fd, int type);
extern void startWhitelist(const char *white_file, const char *logfile, int verbosity, int enable_log);
extern void stopWhitelist();

#endif