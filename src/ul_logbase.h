/*******************************************************************
  uLan Utilities Library - C library of basic reusable constructions

  ul_logbase.h	- base of standard logging facility

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

#ifndef _UL_LOGBASE_H
#define _UL_LOGBASE_H

#include <stdarg.h>
#include "ul_utdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UL_LOGL_MASK (0xff)
#define UL_LOGL_CONT (0x1000)

#define UL_LOGL_FATAL   1
#define UL_LOGL_ERR     2
#define UL_LOGL_MSG     3
#define UL_LOGL_INF     4
#define UL_LOGL_DEB     5
#define UL_LOGL_TRASH   6

#ifndef UL_LOGL_MAX
#define UL_LOGL_MAX     6
#endif

/**
 * struct ul_log_domain - Loggomg domain structure
 * @level:	maximal enabled logging level for domain
 * @name:	logging domain name
 * @flags:	logging domain flags
 */
typedef struct ul_log_domain {
  int level;
  const char *name;
  int flags;
} ul_log_domain_t;

typedef void (ul_log_fnc_t)(ul_log_domain_t *domain, int level,
	const char *format, va_list ap);

void ul_log_redir(ul_log_fnc_t *log_fnc, int add_flags);

int ul_log_check_default_output(void);

void ul_vlog1(ul_log_domain_t *domain, int level,
	const char *format, va_list ap);

void ul_log1(ul_log_domain_t *domain, int level,
	const char *format, ...) UL_ATTR_PRINTF (3, 4);

#ifdef UL_LOG_NOINLINE

int ul_log_cond(ul_log_domain_t *domain, int level);

void ul_vlog(ul_log_domain_t *domain, int level,
	const char *format, va_list ap);

void ul_log(ul_log_domain_t *domain, int level,
	const char *format, ...) UL_ATTR_PRINTF (3, 4);

#else /*UL_LOG_NOINLINE*/

static inline
int ul_log_cond(ul_log_domain_t *domain, int level)
{
  if(!domain || ((level&UL_LOGL_MASK) > UL_LOGL_MAX))
    return 0;
  return (level&UL_LOGL_MASK) <= domain->level;
}

static inline
void ul_vlog(ul_log_domain_t *domain, int level,
	const char *format, va_list ap)
{
  if(!ul_log_cond(domain,level))
    return;
  ul_vlog1(domain, level, format, ap);
}

static inline
void ul_log(ul_log_domain_t *domain, int level,
	const char *format, ...) UL_ATTR_PRINTF (3, 4);

static inline
void ul_log(ul_log_domain_t *domain, int level,
	const char *format, ...)
{
  va_list ap;

  if(!ul_log_cond(domain,level))
    return;
  va_start (ap, format);
  ul_vlog1(domain, level, format, ap);
  va_end (ap);
}

#endif /*UL_LOG_NOINLINE*/

#ifdef __cplusplus
} /* extern "C"*/
#endif

#endif /*_UL_LOGBASE_H*/
