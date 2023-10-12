#ifndef LOGGING_H
#define LOGGING_H

#include <unistd.h>
#include <stdarg.h>

// Log files separated by UID.
#define LOG_DIR "/var/log/keysinuse/"
#define LOG_PATH_TMPL LOG_DIR "keysinuse_%.3s_%08x_%.32s.log"
// /var/log/keysinuse/keysinuse_<level>_<id>_<uid>.log
// (Max len of level + id + uid) - (len of format specifiers) = 30
#define LOG_PATH_LEN sizeof(LOG_PATH_TMPL) + 30
#define LOG_MSG_MAX 256

// log_init should only be run once per process
void set_logging_id(char* id);
void log_init();
void log_cleanup();
void log_debug(const char *message, ...);
void log_error(const char *message, ...);
void log_notice(const char *message, ...);

static void _log_internal(int level, const char *message, va_list args);

#endif // LOGGING_H