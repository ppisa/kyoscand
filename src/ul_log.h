/*******************************************************************
  uLan Utilities Library - C library of basic reusable constructions

  ul_log.h	- standard logging facility

  (C) Copyright 2005 by Pavel Pisa - Originator

  The uLan utilities library can be used, copied and modified under
  next licenses
    - GPL - GNU General Public License
    - LGPL - GNU Lesser General Public License
    - MPL - Mozilla Public License
    - and other licenses added by project originators
  Code can be modified and re-distributed under any combination
  of the above listed licenses. If contributor does not agree with
  some of the licenses, he/she can delete appropriate line.
  Warning, if you delete all lines, you are not allowed to
  distribute source code and/or binaries utilizing code.
  
  See files COPYING and README for details.

 *******************************************************************/

#include <ul_logbase.h>

#define UL_LOG_CUST(log_domain) \
\
ul_log_domain_t log_domain; \
\
static inline \
void ul_loglev(int level, const char *format, ...) UL_ATTR_PRINTF (2, 3);\
static inline \
void ul_vloglev(int level, const char *format, va_list ap) \
{ \
    ul_vlog(&log_domain, level, format, ap); \
} \
\
static inline \
void ul_loglev(int level, const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(level, format, ap); \
    va_end(ap); \
} \
\
static inline \
void ul_logfatal(const char *format, ...) UL_ATTR_PRINTF (1, 2);\
static inline \
void ul_logfatal(const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(UL_LOGL_FATAL, format, ap); \
    va_end(ap); \
}\
\
static inline \
void ul_logerr(const char *format, ...) UL_ATTR_PRINTF (1, 2);\
static inline \
void ul_logerr(const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(UL_LOGL_ERR, format, ap); \
    va_end(ap); \
} \
\
static inline \
void ul_logmsg(const char *format, ...) UL_ATTR_PRINTF (1, 2);\
static inline \
void ul_logmsg(const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(UL_LOGL_MSG, format, ap); \
    va_end(ap); \
} \
\
static inline \
void ul_loginf(const char *format, ...) UL_ATTR_PRINTF (1, 2);\
static inline \
void ul_loginf(const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(UL_LOGL_INF, format, ap); \
    va_end(ap); \
} \
\
static inline \
void ul_logdeb(const char *format, ...) UL_ATTR_PRINTF (1, 2);\
static inline \
void ul_logdeb(const char *format, ...) \
{ \
    va_list ap; \
    va_start(ap, format); \
    ul_vloglev(UL_LOGL_DEB, format, ap); \
    va_end(ap); \
}
