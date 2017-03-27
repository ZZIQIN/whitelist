
#include "whitelist.h"
#include <string.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include <stdarg.h>
#include <errno.h>


#define WHITELIST_MAX_NUMS 10000
#define SUB_WHITELEST_MAX_NUMS 10000>>1
#define WL_TAG_BITS            1


#define REDIS_MAX_LOGMSG_LEN    1024

#define CONN_WL_UPDATE    0


#define HM_HOST 0
#define HM_IPV4 1

uint32_t whitelistMax[33] = {
        0,
        1 << 1, 1 << 2, 1 << 3, 1 << 4,
        1 << 5, 1 << 6, 1 << 7, 1 << 8,
        1 << 9, 1 << 10, 1 << 11, 1 << 12,
        SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS,
        SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS,
        SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS,
        SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS,
        SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, SUB_WHITELEST_MAX_NUMS, WHITELIST_MAX_NUMS
};

typedef struct perm_s {
    uint32_t ip;
    char perm;
} perm_t;

typedef struct permArray {
    perm_t bit32[2][WHITELIST_MAX_NUMS];
    perm_t bit31[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit30[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit29[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit28[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit27[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit26[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit25[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit24[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit23[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit22[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit21[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit20[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit19[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit18[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit17[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit16[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit15[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit14[2][SUB_WHITELEST_MAX_NUMS];
    perm_t bit13[2][1 << 12];
    perm_t bit12[2][1 << 11];
    perm_t bit11[2][1 << 10];
    perm_t bit10[2][1 << 9];
    perm_t bit9[2][1 << 9];
    perm_t bit8[2][1 << 8];
    perm_t bit7[2][1 << 7];
    perm_t bit6[2][1 << 6];
    perm_t bit5[2][1 << 5];
    perm_t bit4[2][1 << 4];
    perm_t bit3[2][1 << 3];
    perm_t bit2[2][1 << 2];
    perm_t bit1[2][1 << 1];
} permArray;

/*
struct redisWhitelist {
    perm_t whitelist[WHITELIST_MAX_NUMS];
    perm_t whitelist_switch[WHITELIST_MAX_NUMS];
};*/
struct permArray whitelist;
perm_t *permPointer[64] = {
        &whitelist.bit1[0][0], &whitelist.bit1[1][0],
        &whitelist.bit2[0][0], &whitelist.bit2[1][0],
        &whitelist.bit3[0][0], &whitelist.bit3[1][0],
        &whitelist.bit4[0][0], &whitelist.bit4[1][0],
        &whitelist.bit5[0][0], &whitelist.bit5[1][0],
        &whitelist.bit6[0][0], &whitelist.bit6[1][0],
        &whitelist.bit7[0][0], &whitelist.bit7[1][0],
        &whitelist.bit8[0][0], &whitelist.bit8[1][0],
        &whitelist.bit9[1][0], &whitelist.bit9[1][0],
        &whitelist.bit10[0][0], &whitelist.bit10[1][0],
        &whitelist.bit11[0][0], &whitelist.bit11[1][0],
        &whitelist.bit12[0][0], &whitelist.bit12[1][0],
        &whitelist.bit13[0][0], &whitelist.bit13[1][0],
        &whitelist.bit14[0][0], &whitelist.bit14[1][0],
        &whitelist.bit15[0][0], &whitelist.bit15[1][0],
        &whitelist.bit16[0][0], &whitelist.bit16[1][0],
        &whitelist.bit17[0][0], &whitelist.bit17[1][0],
        &whitelist.bit18[0][0], &whitelist.bit18[1][0],
        &whitelist.bit19[0][0], &whitelist.bit19[1][0],
        &whitelist.bit20[0][0], &whitelist.bit20[1][0],
        &whitelist.bit21[0][0], &whitelist.bit21[1][0],
        &whitelist.bit22[0][0], &whitelist.bit22[1][0],
        &whitelist.bit23[0][0], &whitelist.bit23[1][0],
        &whitelist.bit24[0][0], &whitelist.bit24[1][0],
        &whitelist.bit25[0][0], &whitelist.bit25[1][0],
        &whitelist.bit26[0][0], &whitelist.bit26[1][0],
        &whitelist.bit27[0][0], &whitelist.bit27[1][0],
        &whitelist.bit28[0][0], &whitelist.bit28[1][0],
        &whitelist.bit29[0][0], &whitelist.bit29[1][0],
        &whitelist.bit30[0][0], &whitelist.bit30[1][0],
        &whitelist.bit31[0][0], &whitelist.bit31[1][0],
        &whitelist.bit32[0][0], &whitelist.bit32[1][0],
};

struct wl_config {
    int whitelist_switch;
    int verbosity;
    char *white_file;
    char *logfile;
    int syslog_enabled;
};

static uint32_t wl_num_tag[32] = {0};
static time_t last_modification = 0;
//struct redisWhitelist redis_w_list;    // connect白名单

static pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t tlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_t thread_id;    //白名单更新线程
static int initialized = 0;

struct wl_config config;

static void *intervalGetWhitelist(void *arg);

static int _intervalGetWhitelist(void *arg, int type);

static int binarySearch(unsigned int num, int type);

static int try_parse_v4_netmask(const char *text, uint32_t *ip, int *b);


void redisLog(int level, const char *fmt, ...);

void redisLogRaw(int level, const char *msg);

static int compare(const void *a, const void *b) {
    return *(uint32_t *) b - *(uint32_t *) a;
}

int findWhitelistByFd(int fd, int type) {
    socklen_t addr_len = sizeof(struct sockaddr_in);

    struct sockaddr sa;
    int err = errno;
    if (getpeername(fd, &sa, &addr_len)) {
        redisLog(REDIS_NOTICE, "fd %d is invalid", fd);
        errno = err;
        return -1;
    }
    return findWhitelist((struct sockaddr_in *) &sa, type);
}

int findWhitelist(struct sockaddr_in *sa, int type) {
    if (!sa) return -1;
    uint32_t ip_to_num = inet_network(inet_ntoa(sa->sin_addr));
    int ret = 0;
    ret = binarySearch(ip_to_num, type);
    if (ret == -1) {
        redisLog(REDIS_NOTICE, "ip %s is forbidden.", (inet_ntoa(sa->sin_addr)));
    }
    return ret;
}

int binarySearch(uint32_t num, int type) {
    int whitelist_tag = -1;
    int whitelist_element_num = -1;
    perm_t *w_list = NULL;
    for (int i = 32; i >= 1; --i) {
        uint32_t tag = wl_num_tag[i - 1];
        whitelist_tag = tag >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);
        whitelist_element_num = (tag << WL_TAG_BITS) >> WL_TAG_BITS;
        w_list = permPointer[i * 2 - 2 + whitelist_tag];
        uint32_t temp = num & (~((1 << (32 - i)) - 1));
        void *hit = bsearch((const void *) &temp, (const void *) w_list, whitelist_element_num, sizeof(perm_t),
                            compare);
        if (hit) {
            perm_t *permt = (perm_t *) hit;
            if (permt->perm & type) {
                return 1;
            }
        }
    }

    return -1;
}

void whitelistJob() {
    if (config.whitelist_switch == WHITELIST_ON) {

        if (pthread_create(&thread_id, NULL, intervalGetWhitelist, NULL) != 0) {
            redisLog(REDIS_WARNING, "Fatal:Can't initialize the whitelist thread.");
            exit(1);
        }
        return;
    }
    redisLog(REDIS_NOTICE, "whitelist : off");
    return;
}

void *intervalGetWhitelist(void *arg) {
    int err = 0;
    struct timeval now;
    struct timespec outtime;
    pthread_mutex_lock(&tlock);
    while (1) {
        if (config.whitelist_switch == WHITELIST_ON) {
            err = _intervalGetWhitelist(arg, CONN_WL_UPDATE);
            if (err == -1) {
                redisLog(REDIS_WARNING, "whitelist update failed!");
            }
            gettimeofday(&now,NULL);
            outtime.tv_sec = now.tv_sec + 2;
            pthread_cond_timedwait(&cond, &tlock, &outtime);
        } else {
            pthread_mutex_unlock(&tlock);
            break;
        }
    }
}

char get_perm(void *buf) {
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

int check_white_file(char *file_name) {
    if (access(file_name, R_OK | F_OK) == -1) {
        redisLog(REDIS_WARNING, "The whitelist(%s) doesn't exist or cannot be readed!", file_name);
        return -1;
    } else {
        struct stat statbuff;
        if (stat(file_name, &statbuff) < 0) {
            redisLog(REDIS_WARNING, "Failed to get the stat of whitelist file [%s]!", file_name);
            return -1;
        } else {
            if (last_modification != statbuff.st_mtime) {
                last_modification = statbuff.st_mtime;
                return 0;
            } else {
                return -1;
            }
        }
    }
}

int _intervalGetWhitelist(void *arg, int type) {
    uint32_t next_tag = -1;
    uint32_t wl_num_tag_temp = 0;
    uint32_t whitelist_tag = -1;
//	uint32_t whitelist_element_num = -1;
    char *file_name = config.white_file;
    perm_t *w_list = NULL;


    whitelist_tag = wl_num_tag[0] >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);
//	whitelist_element_num = (wl_num_tag << WL_TAG_BITS) >> WL_TAG_BITS;
    if (whitelist_tag == 0) {
//        w_list = redis_w_list.whitelist_switch;
        next_tag = 1;
    } else if (whitelist_tag == 1) {
//        w_list = redis_w_list.whitelist;
        next_tag = 0;
    }

    if (check_white_file(file_name) != -1) {
        FILE *white_list_fd = fopen(file_name, "r");
        if (white_list_fd == NULL) {
            redisLog(REDIS_WARNING, "Failed to open the whitelist file[%s]!", file_name);
            return -1;
        } else {
            char buf[44];
            uint32_t cnt[32] = {0};
            bzero(buf, 44);
            uint32_t ip;
            int bits;
            while (fgets(buf, sizeof(buf), white_list_fd)) {
                if (strchr("\n\r#", *buf))
                    continue;

                char *ptr = strpbrk(buf, "\n\r");
                if (ptr)
                    *ptr = '\0';
                ptr = strpbrk(buf, " \t");
                if (!ptr) {
                    redisLog(REDIS_WARNING, "configure bad format[egg: ip rw]");
                    continue;
                } else {
                    *ptr = '\0';
                    if (!try_parse_v4_netmask(buf, &ip, &bits)) {
                        redisLog(REDIS_WARNING, "configure bad format %s", buf);
                        continue;
                    }
                    if (cnt[bits - 1] >= whitelistMax[bits]) {
                        redisLog(REDIS_WARNING, "the number of ip in file [%s] is more than iplist_max, [max:%d]",
                                 file_name, whitelistMax[bits]);
                        break;
                    }
                    char perm = get_perm(++ptr);

                    permPointer[(bits-1)*2+next_tag][cnt[bits - 1]].perm = perm;
                    permPointer[(bits-1)*2+next_tag][cnt[bits - 1]].ip = ip;
                    ++cnt[bits - 1];
//                    redisLog(REDIS_NOTICE, "ip: %s num:%u, bits %d %d ,", buf,ip, bits,bits*2-(1-next_tag)-1);
                    redisLog(REDIS_NOTICE, "ip: %s, perm str: %s, perm:%d", buf, ptr, perm);
                }
            }
            fclose(white_list_fd);
            for (int i = 0; i < 32; ++i) {
                qsort(permPointer[i * 2 + next_tag], cnt[i], sizeof(perm_t), compare);
            }
            for (int i = 31; i >= 0; --i) {
                wl_num_tag_temp = (next_tag << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | cnt[i];
                wl_num_tag[i] = wl_num_tag_temp;
            }
            for (int i = 0; i < 32; ++i) {
                if(!cnt[i]) continue;
                redisLog(REDIS_NOTICE, "whitelist [%s] updated, ip bits %d ,tag: %d, elements_num:%d", file_name, i + 1,
                         next_tag, cnt[i]);
            }
        }

    }
    return 0;
}

void redisLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = {LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING};
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & REDIS_LOG_RAW);

    level &= 0xff; /* clear flags */
    if (level < config.verbosity) return;
    pthread_rwlock_rdlock(&rwlock);
    fp = (config.logfile == NULL) ? stdout : fopen(config.logfile, "a");
    pthread_rwlock_unlock(&rwlock);
    if (!fp) return;

    if (rawmode) {
        fprintf(fp, "%s", msg);
    } else {
        int off;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        off = strftime(buf, sizeof(buf), "%d %b %H:%M:%S.", localtime(&tv.tv_sec));
        snprintf(buf + off, sizeof(buf) - off, "%03d", (int) tv.tv_usec / 1000);
        fprintf(fp, "[%d] %s %c %s\n", (int) getpid(), buf, c[level], msg);
    }
    fflush(fp);

    if (fp != stdout) fclose(fp);

    if (config.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}


void redisLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[REDIS_MAX_LOGMSG_LEN];

    if ((level & 0xff) < config.verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    redisLogRaw(level, msg);
}

void startWhitelist(const char *white_file, const char *logfile, int verbosity, int enable_syslog) {
    pthread_mutex_lock(&mlock);
    if (initialized) {
        pthread_mutex_unlock(&mlock);
        return;
    }
    config.verbosity = verbosity;
    config.syslog_enabled = enable_syslog;
    if (white_file) {
        config.white_file = (char *) malloc(strlen(white_file) + 1);
        strcpy(config.white_file, white_file);
    } else {
        config.white_file = NULL;
    }
    pthread_rwlock_wrlock(&rwlock);
    char *oldlogfile = config.logfile;
    if (logfile) {
        char *newlogfile = (char *) malloc(strlen(logfile) + 1);
        strcpy(newlogfile, logfile);
        config.logfile = newlogfile;
    } else {
        config.logfile = NULL;
    }
    if (oldlogfile) {
        free(oldlogfile);
    }
    pthread_rwlock_unlock(&rwlock);
    config.whitelist_switch = WHITELIST_ON;
    whitelistJob();
    initialized = 1;
    pthread_mutex_unlock(&mlock);
}

void stopWhitelist() {
    pthread_mutex_lock(&mlock);
    if (!initialized) {
        pthread_mutex_unlock(&mlock);
        return;
    }
    config.whitelist_switch = WHITELIST_OFF;

    pthread_mutex_lock(&tlock); //确保更新线程在休眠
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&tlock);
    pthread_join(thread_id, NULL);

    free(config.white_file);
    config.white_file = NULL;
    last_modification = 0;
    initialized = 0;
    pthread_mutex_unlock(&mlock);
}


int try_parse_v4_netmask(const char *text, uint32_t *ip, int *b) {
    const char *digits[4];
    unsigned char addb[4];
    int n = 0, bits = 0;
    char c;

    digits[n++] = text;

    for (const char *p = text; (c = *p); ++p) {
        if (c >= '0' && c <= '9')   /* empty */
            ;
        else if (c == '.') {
            if (n >= 4)
                return HM_HOST;

            digits[n++] = p + 1;
        } else if (c == '*') {
            if (*(p + 1) || n == 1 || *(p - 1) != '.')
                return HM_HOST;

            bits = (n - 1) * 8;
            break;
        } else if (c == '/') {
            char *after;
            bits = strtoul(p + 1, &after, 10);

            if (bits < 0 || *after)
                return HM_HOST;
            if (bits > n * 8)
                return HM_HOST;

            break;
        } else
            return HM_HOST;
    }

    if (n < 4 && bits == 0)
        bits = n * 8;
    if (bits)
        while (n < 4)
            digits[n++] = "0";

    for (n = 0; n < 4; ++n)
        addb[n] = strtoul(digits[n], NULL, 10);

    if (bits == 0)
        bits = 32;

    /* Set unused bits to 0... -A1kmm */
    if (bits < 32 && bits % 8)
        addb[bits / 8] &= ~((1 << (8 - bits % 8)) - 1);
    for (n = bits / 8 + (bits % 8 ? 1 : 0); n < 4; ++n)
        addb[n] = 0;
    if (ip) {
        *ip = addb[0] << 24 | addb[1] << 16 | addb[2] << 8 | addb[3];
    }

    if (b)
        *b = bits;
    return HM_IPV4;
}

//int match_ipv4(const struct sockaddr_in *addr, const struct sockaddr_in *mask, int bits) {
//    const struct sockaddr_in *const v4 = (const struct sockaddr_in *) addr;
//    const struct sockaddr_in *const v4mask = (const struct sockaddr_in *) mask;
//
//    if ((ntohl(v4->sin_addr.s_addr) & ~((1 << (32 - bits)) - 1)) !=
//        ntohl(v4mask->sin_addr.s_addr))
//        return 0;
//    return -1;
//}