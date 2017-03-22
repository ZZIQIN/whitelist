
#include "whitelist.h"
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syslog.h>

#define WHITELIST_MAX_NUMS 10000
#define WL_TAG_BITS			1

#define REDIS_DEBUG 0
#define REDIS_VERBOSE 1
#define REDIS_NOTICE 2
#define REDIS_WARNING 3
#define REDIS_LOG_RAW (1<<10)

#define REDIS_MAX_LOGMSG_LEN    1024

#define CONN_WL_UPDATE	0
#define WRITE_WL_UPDATE	1

typedef struct perm_s {
    uint32_t ip;
    char	 perm;
} perm_t;

struct redisWhitelist{
    perm_t whitelist[WHITELIST_MAX_NUMS];
    perm_t whitelist_switch[WHITELIST_MAX_NUMS];
};

struct wl_config {
    int whitelist_switch;
    int verbosity;
    char *white_file;
    char *logfile;
    int syslog_enabled;
};

static uint32_t wl_num_tag = (1 << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | 0;
static time_t last_modification = 0;
struct redisWhitelist redis_w_list;	// connect白名单

static pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t thread_id;    //白名单更新线程
static int initialized=0;

struct wl_config config;
static void* intervalGetWhitelist(void* arg);
static int _intervalGetWhitelist(void* arg, int type);
static int binarySearch(unsigned int num, int type);
void redisLog(int level, const char *fmt, ...);
void redisLogRaw(int level, const char *msg);
static int compare(const void *a,const void *b) {
    return *(uint32_t *)b - *(uint32_t *)a;
}

int findWhitelist(int fd, int type) {
    socklen_t addr_len = sizeof(struct sockaddr_in);

    struct sockaddr sa;
    getpeername(fd,&sa,&addr_len);
    uint32_t ip_to_num = inet_network(inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr));

    int ret = 0;
    ret = binarySearch(ip_to_num, type);
    if(ret == -1) {
        redisLog(REDIS_NOTICE,"ip %s is forbidden.",(inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr)));
    }
    return ret;
}

int binarySearch(uint32_t num, int type) {
    int whitelist_tag = -1;
    int whitelist_element_num = -1;
    perm_t* w_list = NULL;

    whitelist_tag = wl_num_tag >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);
    whitelist_element_num = (wl_num_tag << WL_TAG_BITS) >> WL_TAG_BITS;

    if (whitelist_tag == 0) {
        w_list = redis_w_list.whitelist;
    } else if (whitelist_tag == 1) {
        w_list = redis_w_list.whitelist_switch;
    }

    void* hit = bsearch((const void*)&num,(const void*)w_list, whitelist_element_num, sizeof(perm_t), compare);
    if (hit) {
        perm_t* permt = (perm_t*)hit;
        if (permt->perm & type) {
            return 1;
        }
    }
    return -1;
}

void whitelistJob() {
    if (config.whitelist_switch == WHITELIST_ON) {

        if(pthread_create(&thread_id,NULL,intervalGetWhitelist,NULL) != 0)
        {
            redisLog(REDIS_WARNING,"Fatal:Can't initialize the whitelist thread.");
            exit(1);
        }
        return;
    }
    redisLog(REDIS_NOTICE, "whitelist : off");
    return;
}

void* intervalGetWhitelist(void* arg) {
    int err = 0;

    while(1) {
        if (config.whitelist_switch == WHITELIST_ON){
            err = _intervalGetWhitelist(arg, CONN_WL_UPDATE);
            if (err == -1) {
                redisLog(REDIS_WARNING,"whitelist update failed!");
            }
            sleep(2);
        }
        else{
            break;
        }
    }
}

char get_perm(void* buf) {
    int buf_len = strlen(buf);
    if (buf_len < 1) {
        redisLog(REDIS_WARNING, "perm buf size invalid");
        return PERM_NONE;
    }
    int cmp_len = 2;
    if (strncmp(buf, "rw", cmp_len) == 0) {
        return PERM_RW;
    }
    if (strncmp(buf, "wr", cmp_len) == 0) {
        return PERM_RW;
    }
    cmp_len = 1;
    if (strncmp(buf, "r", cmp_len) == 0) {
        return PERM_R;
    }
    if (strncmp(buf, "w", cmp_len) == 0) {
        return PERM_W;
    }
    return PERM_NONE;
}

int check_white_file (char* file_name) {
    if(access(file_name,R_OK|F_OK) == -1) {
        redisLog(REDIS_WARNING,"The whitelist(%s) doesn't exist or cannot be readed!", file_name);
        return -1;
    } else {
        struct stat statbuff;
        if(stat(file_name,&statbuff) < 0) {
            redisLog(REDIS_WARNING,"Failed to get the stat of whitelist file [%s]!", file_name);
            return -1;
        } else {
            if(last_modification != statbuff.st_mtime) {
                last_modification = statbuff.st_mtime;
                return 0;
            } else {
                return -1;
            }
        }
    }
}

int _intervalGetWhitelist(void* arg, int type) {
    uint32_t next_tag = -1;
    uint32_t wl_num_tag_temp = 0;
    uint32_t whitelist_tag = -1;
//	uint32_t whitelist_element_num = -1;
    char* file_name = config.white_file;
    perm_t* w_list = NULL;


    whitelist_tag = wl_num_tag >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);
//	whitelist_element_num = (wl_num_tag << WL_TAG_BITS) >> WL_TAG_BITS;
    if(whitelist_tag == 0) {
        w_list = redis_w_list.whitelist_switch;
        next_tag = 1;
    } else if(whitelist_tag == 1) {
        w_list = redis_w_list.whitelist;
        next_tag = 0;
    }

    if (check_white_file(file_name) != -1) {
        FILE *white_list_fd = fopen(file_name,"r");
        if(white_list_fd == NULL) {
            redisLog(REDIS_WARNING,"Failed to open the whitelist file[%s]!", file_name);
            return -1;
        } else {
            char buf[40];
            uint32_t cnt = 0;
            bzero(buf,40);

            while(fgets(buf, sizeof(buf), white_list_fd)) {
                if(strchr("\n\r#", *buf))
                    continue;
                if(cnt >= WHITELIST_MAX_NUMS) {
                    redisLog(REDIS_WARNING,"the number of ip in file [%s] is more than iplist_max, [max:%d]",
                             file_name, WHITELIST_MAX_NUMS);
                    break;
                }
                char* ptr = strpbrk(buf, "\n\r");
                if(ptr)
                    *ptr = '\0';
                ptr = strpbrk(buf, " \t");
                if(!ptr) {
                    redisLog(REDIS_WARNING,"configure bad format[egg: ip rw]");
                    continue;
                } else {
                    *ptr = '\0';
                    w_list[cnt].ip = inet_network(buf);
                    char perm = get_perm(++ptr);
                    w_list[cnt].perm = perm;
                    redisLog(REDIS_NOTICE,"ip: %s, perm str: %s, perm:%d", buf, ptr, perm);
                }
                cnt++;
            }
            fclose(white_list_fd);
            qsort(w_list, cnt, sizeof(perm_t), compare);

            wl_num_tag_temp = (next_tag << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | cnt;
            wl_num_tag = wl_num_tag_temp;
            redisLog(REDIS_NOTICE,"whitelist [%s] updated, tag: %d, elements_num:%d", file_name, next_tag, cnt);
        }

    }
    return 0;
}
void redisLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & REDIS_LOG_RAW);

    level &= 0xff; /* clear flags */
    if (level < config.verbosity) return;

    fp = (config.logfile == NULL) ? stdout : fopen(config.logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;

        gettimeofday(&tv,NULL);
        off = strftime(buf,sizeof(buf),"%d %b %H:%M:%S.",localtime(&tv.tv_sec));
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        fprintf(fp,"[%d] %s %c %s\n",(int)getpid(),buf,c[level],msg);
    }
    fflush(fp);

    if (config.logfile) fclose(fp);

    if (config.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}


void redisLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[REDIS_MAX_LOGMSG_LEN];

    if ((level&0xff) < config.verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    redisLogRaw(level,msg);
}
void startWhitelist(const char *white_file, const char *logfile, int verbosity, int enable_log){
    pthread_mutex_lock(&mlock);
    if(initialized)
        return;
    config.verbosity=verbosity;
    config.syslog_enabled=enable_log;
    if(white_file){
        config.white_file=(char*)malloc(strlen(white_file+1));
        strcpy(config.white_file,white_file);
    }else{
        config.white_file=NULL;
    }
    if(logfile){
        config.logfile=(char*)malloc(strlen(logfile+1));
        strcpy(config.logfile,logfile);
    }else{
        config.logfile=NULL;
    }
    config.whitelist_switch=WHITELIST_ON;
    whitelistJob();
    initialized=1;
    pthread_mutex_unlock(&mlock);
}
void stopWhitelist(){
    pthread_mutex_lock(&mlock);
    if(!initialized) return;
    config.whitelist_switch=WHITELIST_OFF;
    pthread_join(thread_id,NULL);
    free(config.white_file);
    free(config.logfile);
    config.white_file=NULL;
    config.logfile=NULL;
    last_modification=0
    initialized=0;
    pthread_mutex_unlock(&mlock);
}
