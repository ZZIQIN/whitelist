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

#define PERM_NONE     0
#define PERM_R        1
#define PERM_W        2
#define PERM_RW       3

#define REDIS_DEBUG 0
#define REDIS_VERBOSE 1
#define REDIS_NOTICE 2
#define REDIS_WARNING 3
#define REDIS_LOG_RAW (1<<10)

#ifdef	__cplusplus
# define __BEGIN_DECLS	extern "C" {
# define __END_DECLS	}
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif

__BEGIN_DECLS
///
/// \param sa   地址
/// \param type 权限类型
/// \return     -1没有权限  1有权限
extern int findWhitelist(struct sockaddr_in* sa, int type);
///
/// \param fd   socket
/// \param type 权限类型
/// \return     -1没有权限  1有权限
extern int findWhitelistByFd(int fd,int type);

/// 更新白名单
/// \param white_file   白名单名
/// \param logfile      日志名
/// \param verbosity    最小log等级
/// \param enable_syslog 是否输出系统日志 非0输出
extern void startWhitelist(const char *white_file, const char *logfile, int verbosity, int enable_syslog);
///停止更新白名单
extern void stopWhitelist();

__END_DECLS
#endif