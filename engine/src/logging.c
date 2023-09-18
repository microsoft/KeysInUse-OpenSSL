#include "logging.h"

#ifdef __linux__
#include <linux/limits.h>
#include <linux/stat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#endif //__linux__

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#define LOG_ID_LEN_MAX 16
// unix time + , + executable path
#define ID_LEN_MAX 21 + PATH_MAX

static const char *default_log_id = "default";
static const char *default_iden = "";
static char log_id[LOG_ID_LEN_MAX+1] = {0};
static char *iden;
static int iden_len;

// Max file size in bytes. Currently not set but
// may be added as a parameter later if needed
static long max_file_size = __LONG_MAX__;

void set_logging_id(char *id)
{
    // Restrict log id length
    if (id != NULL && *id != '\0')
    {
        strncpy(log_id, id, LOG_ID_LEN_MAX);
        // Ensure log_id is null terminated. If id is longer
        // than id_len then stdncpy will not null terminate log_id
        log_id[LOG_ID_LEN_MAX] = '\0';
    }
    else
    {
        strcpy(log_id, default_log_id);
    }
}

void log_init()
{
    set_logging_id(NULL);
    char *exe_path = NULL;
    time_t start_time = time(NULL);

#ifdef __linux__
    exe_path = OPENSSL_zalloc(PATH_MAX + 1);

    pid_t pid = getpid();
    int len_sym_path = snprintf(NULL, 0, "/proc/%d/exe", pid) + 1;
    char *sym_path = OPENSSL_zalloc(len_sym_path);

    if (snprintf(sym_path, len_sym_path, "/proc/%d/exe", pid) > 0)
    {
        readlink(sym_path, exe_path, PATH_MAX + 1);
    }
    else
    {
        strcpy(exe_path, "");
    }

    OPENSSL_free(sym_path);
#endif //__linux__

    if (exe_path)
    {
        iden_len = snprintf(NULL, 0, "%ld,%s", start_time, exe_path);
        iden_len = iden_len > ID_LEN_MAX ? ID_LEN_MAX : iden_len;

        iden = OPENSSL_malloc(iden_len + 1);

        // If sprintf fails, we can still log key usage. This should never
        // happen, but we don't want to cause any crashes in case it does.
        if (iden == NULL ||
            snprintf(iden, iden_len + 1, "%ld,%s", start_time, exe_path) < 0)
        {
            OPENSSL_free(iden);
            iden = (char*)default_iden;
        }
    }

    OPENSSL_free(exe_path);
}

void log_cleanup()
{
    if (iden != default_iden)
    {
        OPENSSL_free(iden);
        iden = (char *)default_iden;
    }
}

void log_debug(const char *message, ...)
{
#ifdef DEBUG
    va_list args;
    va_start(args, message);
    _log_internal(LOG_DEBUG, message, args);
#endif // DEBUG
}

void log_error(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    _log_internal(LOG_ERR, message, args);
}

void log_notice(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    _log_internal(LOG_NOTICE, message, args);
}

static void _log_internal(int level, const char *message, va_list args)
{
    char *level_str = "";
    char log_path[LOG_PATH_LEN + 1];
    char msg_buf[LOG_MSG_MAX];
    int msg_len;

    switch (level)
    {
#ifdef DEBUG
    case LOG_DEBUG:
        level_str = "dbg";
        break;
#endif // DEBUG
    case LOG_ERR:
        level_str = "err";
        break;
    case LOG_NOTICE:
    default:
        level_str = "not";
        break;
    }

    uid_t euid = geteuid();

    sprintf(log_path, LOG_PATH_TMPL, level_str, euid, log_id);

    if ((msg_len = vsnprintf(msg_buf, LOG_MSG_MAX, message, args)) > 0)
    {
#ifdef __linux__
        int len = iden_len + msg_len + 6;
        char prefixed_msg[len + 1];
        strcpy(prefixed_msg, "");
        strcat(prefixed_msg, iden);
        strcat(prefixed_msg, ",");
        strcat(prefixed_msg, level_str);
        strcat(prefixed_msg, "!");
        strcat(prefixed_msg, msg_buf);
        strcat(prefixed_msg, "\n");

        // Check the log file to make sure:
        // 1. File isn't a symlink
        // 2. File permissions are 0200
        // 3. Logging won't exceed maximum file size
        struct statx sb;
        if (statx(0, log_path, AT_SYMLINK_NOFOLLOW, STATX_MODE | STATX_SIZE, &sb) != -1)
        {
            int isBadFile = 0;
            if (S_ISLNK(sb.stx_mode))
            {
                if (level > LOG_ERR)
                {
                    log_error("Found symlink at %s. Removing file", log_path);
                }
                isBadFile = 1;
            }

            if (!isBadFile && (sb.stx_mode & 0777) != 0200)
            {
                if (level > LOG_ERR)
                {
                    log_error("Found unexpected permissions (%o) on %s. Removing file", (sb.stx_mode & 0777), log_path);
                }
                isBadFile = 1;
            }

            if (isBadFile)
            {
                if (remove(log_path) != 0)
                {
                    if (level > LOG_ERR)
                    {
                        log_error("Failed to remove bad log file at %s,SYS_%d", log_path, errno);
                    }
                    return;
                }
            }
            else if (sb.stx_size + len > max_file_size)
            {
                if (level > LOG_ERR)
                {
                    log_error("Failed to log to %s. File size capped at %ld bytes", log_path, max_file_size);
                }
                return;
            }
        }
        else if (errno != ENOENT)
        {
            if (level > LOG_ERR)
            {
                log_error("Failed to stat file at %s,SYS_%d", log_path, errno);
            }
            return;
        }

        // Log files are separated by uid. Only write access is needed
        int fd;
        for (int i = 0; i < 3; i++)
        {
            fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0200);
            if (fd >= 0 || errno != EACCES)
            {
                break;
            }
            usleep(500); // Sleep for 500 microseconds
        }

        if (fd < 0)
        {
            if (level > LOG_ERR)
            {
                log_error("Failed to open log file for appending at %s,SYS_%d", log_path, errno);
            }
            return;
        }
        fchmod(fd, 0200);

        if (write(fd, prefixed_msg, len) < 0 && level > LOG_ERR)
        {
            log_error("Failed to write to log file at %s,SYS_%d", log_path, errno);
        }

        if (close(fd) < 0 && level > LOG_ERR)
        {
            log_error("Failed to close log file at %s,SYS_%d", log_path, errno);
        }
#endif //__linux__
#ifdef _WIN32
        printf("%s[%s] %s\n", iden, level_str, msg_buf);
#endif //_WIN32
    }
}