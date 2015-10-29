/*******************************************************************
  uLan Utilities Library - C library of basic reusable constructions

  ul_logbase.c	- base of standard logging facility

  (C) Copyright 2003 by Pavel Pisa - Originator

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

#ifndef __RTL__

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>

#else /*__RTL__*/

#include <rtl.h>
#include <string.h>
#include <signal.h>
#include <posix/unistd.h>

#endif /*__RTL__*/

#include "ul_utdefs.h"
#include "ul_logbase.h"


int ul_debug_flg;
int ul_log_cutoff_level;   

#ifdef UL_LOG_NOINLINE

int ul_log_cond(ul_log_domain_t *domain, int level)
{
  if(!domain || ((level&UL_LOGL_MASK) > UL_LOGL_MAX))
    return 0;
  return (level&UL_LOGL_MASK) <= domain->level;
}

void ul_vlog(ul_log_domain_t *domain, int level,
	const char *format, va_list ap)
{
  if(!ul_log_cond(domain,level))
    return;
  ul_vlog1(domain, level, format, ap);
}

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


void
ul_log_fnc_default(ul_log_domain_t *domain, int level,
	const char *format, va_list ap);

ul_log_fnc_t *ul_log_output;
#ifndef __RTL__
FILE *ul_log_default_file;
#endif /*__RTL__*/

/**
 * ul_log - generic logging facility for ULUT library
 * @domain: pointer to domain of debugging messages
 * @level:  severity level
 * @format: printf style format followed by arguments
 *
 * This functions is used for logging of various events.
 * If not overridden by application, logged messages goes to the stderr.
 * Environment variable %UL_LOG_FILENAME can be used to redirect 
 * output to file. Environment variable %UL_DEBUG_FLG can be used
 * to select different set of logged events through ul_debug_flg.
 *
 * Note: There is a global variable %ul_log_cutoff_level. 
 * Only the messages with %level <= %ul_log_cutoff_level will be logged.
 */           

void
ul_log1(ul_log_domain_t *domain, int level,
       const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  ul_vlog1(domain,level,format,ap);
  va_end(ap); 
}

void
ul_vlog1(ul_log_domain_t *domain, int level,
       const char *format, va_list ap)
{
  if(ul_log_cutoff_level) {
      if((level & UL_LOGL_MASK) > ul_log_cutoff_level) return;
  }
  if(ul_log_output==NULL) {
    ul_log_check_default_output();
  }
  if(ul_log_output)
    (*ul_log_output)(domain,level,format,ap);
}

/**
 * ul_log_redir - redirects default log output function
 * @log_fnc: new log output function. Value NULL resets
 *           to default function
 * @add_flags: some more flags
 */

void
ul_log_redir(ul_log_fnc_t *log_fnc, int add_flags)
{
  if(log_fnc==NULL) log_fnc=ul_log_fnc_default;
  ul_log_output=log_fnc;
}

#ifndef __RTL__
void
ul_log_fnc_default(ul_log_domain_t *domain, int level,
	const char *format, va_list ap)
{
  if(!(level&UL_LOGL_CONT)) {
    level&=UL_LOGL_MASK;
    if(level)
      fprintf(ul_log_default_file,"<%d>",level);
    if(domain && domain->name)
      fprintf(ul_log_default_file,"%s: ",domain->name);
  }
  vfprintf(ul_log_default_file, format, ap);
  fflush(ul_log_default_file);
}


#else /*__RTL__*/
void
ul_log_fnc_default(ul_log_domain_t *domain, int level,
	const char *format, va_list ap)
{
  if(!(level&UL_LOGL_CONT)) {
    level&=UL_LOGL_MASK;
    if(level)
      rtl_printf("<%d>",level);
    if(domain && domain->name)
      rtl_printf("%s: ",domain->name);
  }
  rtl_vprintf(format, ap);
}

#endif /*__RTL__*/

int
ul_log_check_default_output(void)
{
 #ifndef __RTL__
  char *s;
  char *log_fname;
 #endif /*__RTL__*/

  if(ul_log_output!=NULL)
    return 0;

  ul_log_output=ul_log_fnc_default;
 #ifndef __RTL__
  if((log_fname=getenv("UL_LOG_FILENAME"))!=NULL){
    ul_log_default_file=fopen(log_fname,"a");
  }
  if(ul_log_default_file==NULL)
    ul_log_default_file=stderr;
  if(!ul_debug_flg&&((s=getenv("UL_DEBUG_FLG"))!=NULL)){
    ul_debug_flg=atoi(s);
  }
  if((s = getenv("UL_LOG_CUTTOFF")) != NULL) {
      ul_log_cutoff_level = atoi(s);
  }
 #endif /*__RTL__*/
  return 0;
}

