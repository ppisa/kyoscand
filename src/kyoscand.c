/*************************************************************************
 * kyoscand - Kyocera Scan System F PC Daemon                            *
 * (Known to work with Kyocera KM-1650, TASKalfa 221, Olivetti 2200MF)   *
 *                                                                       *
 * (C) Copyright 2006 - 2012 by Pavel Pisa - Originator                  *
 *                              <pisa@cmp.felk.cvut.cz>                  *
 *                                                                       *
 * This program is free software; you can redistribute it and/or modify  *
 * it under the terms of the GNU General Public License as published by  *
 * the Free Software Foundation; either version 2 of the License, or     *
 * (at your option) any later version.                                   *
 *                                                                       *
 * This program is distributed in the hope that it will be useful,       *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 * GNU General Public License for more details.                          *
 *                                                                       *
 * You should have received a copy of the GNU General Public License     *
 * along with this program; if not, write to the                         *
 * Free Software Foundation, Inc.,                                       *
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                       *
 * See file COPYING for details.                                         *
 *                                                                       *
 *************************************************************************/

#define WITH_DAEMON
#define HAS_GETOPT_LONG
#define _GNU_SOURCE
#define PROGRAM_VERSION "0.0.5"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <semaphore.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>

#ifdef WITH_DAEMON
#include <syslog.h>
#endif /*WITH_DAEMON*/

#include <ul_log.h>

extern UL_LOG_CUST(ulogd_kyoscand);

#define UL_LOGL_DEF UL_LOGL_MSG
//#define UL_LOGL_DEF UL_LOGL_DEB

ul_log_domain_t ulogd_kyoscand = {UL_LOGL_DEF, "kyoscand"};

/********************************************************************/

#ifdef WITH_DAEMON

int syslog_log_priorities[] = {
  [UL_LOGL_FATAL] = LOG_CRIT,
  [UL_LOGL_ERR]   = LOG_ERR,
  [UL_LOGL_MSG]   = LOG_WARNING,
  [UL_LOGL_INF]   = LOG_INFO,
  [UL_LOGL_DEB]   = LOG_DEBUG,
  [UL_LOGL_TRASH] = LOG_DEBUG,
};

void
syslog_log_fnc(ul_log_domain_t *domain, int level,
        const char *format, va_list ap)
{
  char *str;

  level = syslog_log_priorities[level & UL_LOGL_MASK];
  if(vasprintf(&str, format, ap)<0)
      return;
  if((domain == NULL) || (domain->name==NULL))
      syslog(LOG_MAKEPRI(LOG_LOCAL5, level), "%s", str);
  else
      syslog(LOG_MAKEPRI(LOG_LOCAL5, level), "%s:%s", domain->name, str);
  free(str);
}

static int syslog_log_init(void)
{
  if(getenv("UL_LOG_FILENAME")==NULL) {
    openlog ("kyoscand", 0, LOG_LOCAL3);
    ul_log_redir(syslog_log_fnc, 0);
  }
  return 0;
}

static int daemon_init(void)
{
  pid_t pid;

  if ((pid = fork()) < 0) {
      return -1;
  } else {
      if (pid != 0) {
          exit(0);	/* parent vanishes */
      }
  }
  /* child process */

  close(0);
  close(1);
  close(2);

  setsid();
  setpgid (0, 0);
  umask(022);

  return 0;
}

#endif /*WITH_DAEMON*/

/********************************************************************/

#define HEXDUMP_ROW_MAX 32

void ul_log_hexdump(ul_log_domain_t *domain, int level, char *prefix,
                    const void *buff, unsigned long start, unsigned long len, int row,
		    int flags)
{
  static const char xdigs[] = "0123456789ABCDEF";
  unsigned long addr=start;
  unsigned char *p=(unsigned char *)buff;
  unsigned char c;
  int cnt;
  int i;
  char row_hex[HEXDUMP_ROW_MAX*3];
  char row_chr[HEXDUMP_ROW_MAX*3];
  char *p_hex;
  char *p_chr;

  if(!ul_log_cond(domain, level))
    return;

  if(!prefix)
    prefix="";

  if(!row)
    row=16;

  if(row>HEXDUMP_ROW_MAX)
    row=HEXDUMP_ROW_MAX;

  while(len){
    cnt=(len>row)?row:len;
    len-=cnt;
    p_hex=row_hex;
    p_chr=row_chr;
    for(i=cnt;i--;){
      c=*(p++);
      *(p_hex++)=xdigs[(c>>4)&0xf];
      *(p_hex++)=xdigs[c&0xf];
      *(p_hex++)=' ';
      if((c<0x20)||(c>0x80))
        c='.';
      *(p_chr++)=c;
    }
    *(--p_hex)=0;
    *(--p_chr)=0;
    ul_log(domain, level, "%s%04lx:%s  %s\n", prefix, addr, row_hex, row_chr);
    addr+=cnt;
  }
  return;
}

/********************************************************************/

char pc2kyo_data_0[] = {
0x4f, 0x4b, 0x00, 0x05 };
char kyo2pc_data_0[] = {
0x00, 0x06, 0x34, 0x00, 0x00, 0x02, 0x00, 0x00 };
char pc2kyo_data_1[] = {
0x00, 0x6a, 0x34, 0x10, 0x00, 0x01, 0x00, 0x10,
0x00, 0x1b, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00,
/* "TIFF-G4MMR" "PDF-G4MMR" "TIFF-G3MH"*/
0x00, 0x00, 0x54, 0x49, 0x46, 0x46, 0x2d, 0x47,
0x34, 0x4d, 0x4d, 0x52, 0x00, 0x50, 0x44, 0x46,
0x2d, 0x47, 0x34, 0x4d, 0x4d, 0x52, 0x00, 0x54,
0x49, 0x46, 0x46, 0x2d, 0x47, 0x33, 0x4d, 0x48,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00 };
char kyo2pc_data_1[] = {
0x02, 0x1c, 0x34, 0x02, 0x00, 0x01, 0x00, 0x08,
/*"kyoscan" "NSN_SKAN:kyoscan"*/
0x00, 0x10, 0x6b, 0x79, 0x6f, 0x73, 0x63, 0x61,
0x6e, 0x00, 0x4e, 0x53, 0x4e, 0x5f, 0x53, 0x4b,
0x41, 0x4e, 0x3a, 0x6b, 0x79, 0x6f, 0x73, 0x63,
0x61, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
char pc2kyo_data_2[] = {
0x00, 0x0a, 0x34, 0x11, 0x00, 0x01, 0x00, 0x00,
0xff, 0xff, 0xff, 0xff };
char kyo2pc_data_2[] = {
0x00, 0x54, 0x30, 0x01, 0x00, 0x01, 0x00, 0x00,
0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* "SCAN0003_000.tif" */
0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x53, 0x43,
0x41, 0x4e, 0x30, 0x30, 0x30, 0x33, 0x5f, 0x30,
0x30, 0x30, 0x2e, 0x74, 0x69, 0x66, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
char kyo2pc_data_3[] = {
0x60, 0x00, 0x49, 0x49, 0x2a, 0x00, 0x08, 0x00 };
/* ... */
char kyo2pc_data_480[] = {
0x00, 0x04, 0x30, 0x02, 0x00, 0x00 };
char kyo2pc_data_481[] = {
0x00, 0x04, 0x30, 0x05, 0x6c, 0x7b };
char pc2kyo_data_3[] = {
0x00, 0x06, 0x30, 0x15, 0x00, 0x01, 0x00, 0x00 };
char kyo2pc_data_482[] = {
0x00, 0x04, 0x30, 0x03, 0x00, 0x00 };
char pc2kyo_data_4[] = {
0x00, 0x06, 0x30, 0x13, 0x00, 0x01, 0x00, 0x00 };

#define CON_FDTYPE_FILE   0
#define CON_FDTYPE_SOCKET 1

typedef struct {
  int fdin;
  int fdout;
  int fdtype;
  struct sockaddr_in peer_addr;
  int errcode;
  int expected_bytes;
  int rec_bytes;
  int timeout;
  void *app_options;
} con_params_t;

typedef struct {
  char *base_dir;
} kyoscan_app_options_t;

#define KYOSCAND_PORT 37100

pthread_mutex_t file_counter_mutex=PTHREAD_MUTEX_INITIALIZER;
int file_counter;

pthread_mutex_t thread_counter_mutex=PTHREAD_MUTEX_INITIALIZER;
int thread_counter;
int thread_limit=10;

int con_write(con_params_t *con, const void *buff, size_t bytes)
{
  ssize_t retval;

  while(bytes>0){
    retval=write(con->fdout,buff,bytes);
    if(retval<0){
      if(errno==EINTR)
        continue;
      ul_logmsg("con_write failed %s\n",strerror(errno));
      return -1;
    }
    bytes-=retval;
    buff=(char*)buff+retval;
  }
  return 0;
}

int con_read(con_params_t *con, void *buff, size_t bytes)
{
  ssize_t retval;
  struct timeval tv;
  fd_set rfds;
  int retfd;

  FD_ZERO(&rfds);

  while(bytes>0){
    tv.tv_sec = con->timeout;
    tv.tv_usec = 0;

    FD_SET(con->fdin, &rfds);
    retfd=select(con->fdin+1, &rfds, NULL, NULL, con->timeout?&tv:NULL);
    if(retfd<0){
      if(errno==EINTR)
        continue;
      ul_logmsg("con_read wait failed %s\n",strerror(errno));
      return -1;
    }

    if(retfd==0){
      ul_logmsg("con_read wait timeout\n");
      return -1;
    }

    retval=read(con->fdin,buff,bytes);
    if(retval<0){
      if(errno==EINTR)
        continue;
      ul_logmsg("con_read failed %s\n",strerror(errno));
      return -1;
    }
    if(retval==0){
      ul_logmsg("con_read remote peer disconnected\n");
      return -1;
    }
    bytes-=retval;
    buff=(char*)buff+retval;
  }
  return 0;
}

ssize_t con_block_read(con_params_t *con, void **pbuff, size_t max_bytes)
{
  void *buff;
  unsigned char len_data[2];
  size_t bytes;
  if(con_read(con, &len_data, 2))
    return -1;
  bytes=(len_data[0]<<8)|len_data[1];
  if(bytes>max_bytes){
    ul_logmsg("con_block_read indicates %ld bytes > %ld max_bytes\n",(long)bytes,(long)max_bytes);
    return -1;
  }
  buff=malloc(bytes);
  if(buff==NULL){
    ul_logmsg("con_block_read cannot allocate buffer for %ld\n",(long)bytes);
    return -1;
  }
  if(con_read(con, buff, bytes)){
    free(buff);
    return -1;
  }
  ul_logdeb("con_block_read received %ld\n",(long)bytes);
  *pbuff=buff;
  return bytes;
}

void block_hexdump(char *prefix, const void *buff, unsigned long len)
{
  ul_log_hexdump(&ulogd_kyoscand, UL_LOGL_DEB, prefix, buff, 0, len, 16, 0);
}

static inline
unsigned long block_get_uint16(void *ptr, size_t offs)
{
  unsigned char *p=(unsigned char *)ptr;
  p+=offs;
  return ((unsigned)p[0]<<8)|p[1];
}

static inline
unsigned long block_get_uint32(void *ptr, size_t offs)
{
  unsigned char *p=(unsigned char *)ptr;
  p+=offs;
  return ((unsigned long)p[0]<<24)|((unsigned long)p[1]<<16)|
         ((unsigned)p[2]<<8)|p[3];
}

int kyoscan_receive_file(con_params_t *con, char *file_name)
{
  FILE *f=NULL;
  ssize_t block_size;
  ssize_t regularsize=0;
  int res;
  void *block=NULL;
  int retval=-1;

  f=fopen(file_name,"w");
  if(f==NULL){
    ul_logerr("cannot open filename \"%s\" for write %s\n",file_name,strerror(errno));
    return -1;
  }

  do{
    block_size=con_block_read(con,&block,0x10000);
    if(block_size<0){
      break;
    }

    if(!block){
      if(!block_size)
	continue;
      ul_logerr("returned NULL block for block_size %ld\n", (long)block_size);
      break;
    }

    if(block_size>regularsize)
      regularsize=block_size;

    res=fwrite(block,block_size,1,f);
    if(res!=1){
      if(res>=0){
        ul_logerr("fwrite failed no space for data (res=%d)\n", res);
      }else{
        ul_logerr("fwrite failed %s\n",strerror(errno));
      }
    }

    if(block_size==4)
      block_hexdump("kyo2pc ", block, block_size);
    free(block); block=NULL;

    if(block_size<regularsize){
      retval=0;
      break;
    }
  }while(1);

  fclose(f);

  if(block)
    free(block);

  return retval;
}

int kyoscan_transfer(con_params_t *con)
{
  int retval=-1;
  ssize_t block_size;
  int res;
  void *block=NULL;
  unsigned char *p;
  int file_num;
  char *file_name;
  int code;
  int subcode;
  unsigned destination=0;
  kyoscan_app_options_t *options;

  options=(kyoscan_app_options_t *)con->app_options;

  /* Send OK */
  res=con_write(con,pc2kyo_data_0,sizeof(pc2kyo_data_0));
  if(res<0){
    goto finalize;
  }
  ul_logdeb("sent pc2kyo_data_0\n");

  do{
    block_size=con_block_read(con,&block,0x10000);
    if(block_size<0){
      goto finalize;
    }
    block_hexdump("kyo2pc ", block, block_size);

    if(block_size<2){
      ul_logerr("zero length block received %ld\n", (long)block_size);
      goto finalize;
    }
    p=(unsigned char *)block;
    code=*(p++);
    subcode=*(p++);

    switch(code){
      case 0x30:
        switch(subcode){
	  case 0x01:
            file_name=NULL;
	    ul_logdeb("image data start\n");

	    pthread_mutex_lock(&file_counter_mutex);
	    file_num=file_counter;
	    file_counter++;
	    pthread_mutex_unlock(&file_counter_mutex);

            if(1){
	      int n;
	      n=block_size-0x24;
	      if(n>=1){
	        file_name=strndup(block+0x24,n);
	        if(!file_name){
		  ul_logerr("cannot allocate space for filename\n");
        	  goto finalize;
	        }
	      }
	      for(n=0;n<strlen(file_name);n++){
	        if(file_name[n]=='/'){
		  file_name[n]='_';
		}
	      }
	    }
	    if(!file_name){
	      res=asprintf(&file_name, "scan%03d.tiff", file_num);
	      if(!file_name&&(res<0)){
		ul_logerr("cannot allocate space for filename\n");
        	goto finalize;
	      }
	    }
	    if(options&&options->base_dir){
	      char *s=NULL;
	      char *d=NULL;
              struct stat status;

	      res=asprintf(&d, "%s/%03d", options->base_dir, destination);
	      if(d&&(res>=0))
	        res=asprintf(&s, "%s/%s", d, file_name);
              free(file_name);
	      if(!s||(res<0)){
	        if(d)
		  free(d);
		ul_logerr("cannot allocate space for filename\n");
        	goto finalize;
	      }
	      file_name=s;

              if(stat(d, &status)){
 	        if(errno!=ENOENT){
                  ul_logerr("stat \"%s\" failed %s\n",d,strerror(errno));
		  free(d);
		  free(file_name);
        	  goto finalize;
		}
	        if(mkdir(d, S_IRWXU | S_IRWXG)){
                  if(errno!=EEXIST){
                    ul_logerr("mkdir \"%s\" failed %s\n",d,strerror(errno));
		    free(d);
		    free(file_name);
        	    goto finalize;
		  }
		}
              }else{
	        if(!S_ISDIR(status.st_mode)){
                  ul_logerr("path \"%s\" is not a directory\n", d);
		  free(d);
		  free(file_name);
        	  goto finalize;
		}
	      }
	      free(d);
	    }
	    ul_loginf("receiving file %s\n", file_name);
            res=kyoscan_receive_file(con, file_name);
            free(file_name);
	    if(res<0){
	      ul_logerr("file receive failed\n");
              goto finalize;
	    }
	    break;
	  case 0x02:
	    ul_logdeb("image data end\n");
	    break;
	  case 0x03:
	    res=con_write(con,pc2kyo_data_4,sizeof(pc2kyo_data_4));
	    if(res<0){
              goto finalize;
	    }
	    ul_logdeb("sent pc2kyo_data_4\n");
            ul_loginf("communication finished\n");
            retval=0;
            goto finalize;
	  case 0x05:
	    res=con_write(con,pc2kyo_data_3,sizeof(pc2kyo_data_3));
	    if(res<0){
              goto finalize;
	    }
	    ul_logdeb("sent pc2kyo_data_3\n");
	    break;
	  default:
            ul_logerr("code 0x%02X, unknown subcode 0x%02X\n", code, subcode);
            goto finalize;
	}
	break;
      case 0x34:
        switch(subcode){
	  case 0x00:
	    res=con_write(con,pc2kyo_data_1,sizeof(pc2kyo_data_1));
	    if(res<0){
              goto finalize;
	    }
	    ul_logdeb("sent pc2kyo_data_1\n");
	    break;
	  case 0x02:
	    if(block_size>=4){
              destination=block_get_uint16(block,0x02);
	      ul_logdeb("selected destination %d\n",destination);
	    }
	    res=con_write(con,pc2kyo_data_2,sizeof(pc2kyo_data_2));
	    if(res<0){
              goto finalize;
	    }
	    ul_logdeb("sent pc2kyo_data_2\n");
	    break;
	  default:
            ul_logerr("code 0x%02X, unknown subcode 0x%02X\n", code, subcode);
            goto finalize;
	}
	break;
      case 0x36:
        switch(subcode){
	  case 0x01:
            ul_loginf("received disconnect mark\n");
            retval=0;
            goto finalize;
	  default:
            ul_logerr("code 0x%02X, unknown subcode 0x%02X\n", code, subcode);
            goto finalize;
	}
	break;
      default:
        ul_logerr("unknown code 0x%02X, subcode 0x%02X\n", code, subcode);
        goto finalize;
    }

    free(block); block=NULL;

  }while(1);

finalize:

  if(block)
    free(block);

  close(con->fdin);
  if(con->fdout!=con->fdin)
    close(con->fdout);

  ul_logmsg("kyoscan transfer finished with %d result\n", retval);

  pthread_mutex_lock(&file_counter_mutex);
  thread_counter--;
  pthread_mutex_unlock(&file_counter_mutex);

  return retval;
}

/********************************************************************/


void *thread_scanclient(void *arg)
{
  con_params_t *con=(con_params_t *)arg;

  kyoscan_transfer(con);

  return NULL;
}


int server_kyoscand(int port_number, kyoscan_app_options_t *options)
{
  int sockfd, new_fd;
  struct sockaddr_in my_addr;
  struct sockaddr_in their_addr;
  unsigned int sin_size;
  int yes = 1;
  int retval;
  pthread_t thread;
  con_params_t *con;

  sockfd = socket(PF_INET, SOCK_STREAM, 0); // do some error checking!
  if(sockfd==-1){
    ul_logerr("socket creation failed %s\n",strerror(errno));
    return -1;
  }

  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    ul_logerr("set of SO_REUSEADDR failed %s\n",strerror(errno));
    return -1;
  }

  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(port_number);
  my_addr.sin_addr.s_addr = INADDR_ANY;

  retval = bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
  if (retval != 0) {
    ul_logerr("bind for port %d failed %s\n",port_number, strerror(errno));
    return -1;
  }

  retval = listen(sockfd, 5);
  if (retval != 0) {
    ul_logerr("listen for port %d failed %s\n",port_number, strerror(errno));
    return -1;
  }

  ul_logmsg("server is listening for connections at port %d\n",port_number);

  while (1) {
    sin_size = sizeof(struct sockaddr_in);
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

    if (new_fd < 0) {
      ul_logerr("accept for port %d failed %s\n",port_number, strerror(errno));
      return -1;
    }

    con=malloc(sizeof(con_params_t));
    if(!con){
      ul_logerr("cannot allocate connection structure\n");
      close(new_fd);
      continue;
    }

    memset(con,0,sizeof(con_params_t));
    con->fdin=new_fd;
    con->fdout=new_fd;
    con->fdtype=CON_FDTYPE_SOCKET;
    con->errcode=0;
    memcpy(&con->peer_addr, &their_addr, sizeof(struct sockaddr));
    con->app_options=options;

    ul_loginf("client connected from %s:%d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));

    pthread_mutex_lock(&thread_counter_mutex);
    if(thread_counter>=thread_limit){
      pthread_mutex_unlock(&thread_counter_mutex);
      ul_logerr("concurrent clients count limit reached\n");
      close(new_fd);
      free(con);
      continue;
    }
    thread_counter++;
    pthread_mutex_unlock(&thread_counter_mutex);

    retval=pthread_create(&thread, NULL, thread_scanclient, con);
    if(retval) {
      ul_logerr("cannot create new thread %s\n", strerror(errno));
      close(new_fd);
      free(con);
      pthread_mutex_lock(&thread_counter_mutex);
      thread_counter--;
      pthread_mutex_unlock(&thread_counter_mutex);
      continue;
    }

    pthread_detach(thread);
  }
}

int inetd_kyoscan(kyoscan_app_options_t *options)
{
  int retval;
  con_params_t *con;

  con=malloc(sizeof(con_params_t));
  if(!con){
    ul_logerr("cannot allocate connection structure\n");
    return -1;
  }

  memset(con,0,sizeof(con_params_t));
  con->fdin=fileno(stdin);
  con->fdout=fileno(stdout);
  con->fdtype=CON_FDTYPE_FILE;
  con->errcode=0;
  con->app_options=options;

  retval=kyoscan_transfer(con);
  return retval;
}

/********************************************************************/

int kyoscand_port_number=KYOSCAND_PORT;
int daemon_fl=0;
int syslog_fl=0;
int inetd_fl=0;
int umask_set=-1;

kyoscan_app_options_t kyoscan_app_options;

static void
usage(void)
{
  printf("usage: kyoscand <parameters>\n");
 #ifdef WITH_DAEMON
  printf("  -D, --daemon             daemonize\n");
  printf("  -S, --syslog             logging to syslog\n");
  printf("  -I, --inetd              command is run from inetd\n");
 #endif /*WITH_DAEMON*/
  printf("  -p, --port <num>         select target connection HW type [%d]\n",kyoscand_port_number);
  printf("  -d, --base-dir <string>  select directory where to store scans [current]\n");
  printf("  -u, --umask <num>        set umask to given value before startup\n");
  printf("  -g, --log-level <num>    default log level [%d]\n",ulogd_kyoscand.level);
  printf("  -V, --version            print program version\n");
  printf("  -h, --help               this usage screen\n");
}

int main(int argc, char *argv[])
{

  int res;

  static const struct option long_opts[] = {
   #ifdef WITH_DAEMON
    { "daemon",   0, 0, 'D' },
    { "syslog",   0, 0, 'S' },
   #endif /*WITH_DAEMON*/
    { "inetd",    0, 0, 'I' },
    { "port",     1, 0, 'p' },
    { "base-dir", 1, 0, 'd'},
    { "umask",    1, 0, 'u' },
    { "log-level",1, 0, 'g'},
    { "version",  0, 0, 'V' },
    { "help",     0, 0, 'h' },
    { 0, 0, 0, 0}
  };
  static const char short_opts[]={"DSIp:d:u:g:Vh"};
  int opt;
  long l;

 #ifndef HAS_GETOPT_LONG
  while ((opt = getopt(argc, argv, short_opts)) != EOF)
 #else
  while ((opt = getopt_long(argc, argv, short_opts,
			    &long_opts[0], NULL)) != EOF)
 #endif
  switch (opt) {
    case 'D':
      daemon_fl=1;
      break;
    case 'S':
      syslog_fl=1;
      break;
    case 'I':
      inetd_fl=1;
      break;
    case 'p':
      kyoscand_port_number=strtoul(optarg,NULL,0);
      break;
    case 'd':
      kyoscan_app_options.base_dir=optarg;
      break;
    case 'u':
      umask_set=strtoul(optarg,NULL,0);
      break;
    case 'g':
      l=strtoul(optarg,NULL,0);
      if((l<0)||(l>UL_LOGL_MAX)){
        fprintf(stderr,"required log level is out of range");
        exit(3);
      }
      ulogd_kyoscand.level=l;
      break;
    case 'V':
      fputs("kyoscand version " PROGRAM_VERSION "\n", stdout);
      exit(0);
    case 'h':
    default:
      usage();
      exit(opt == 'h' ? 0 : 1);
  }

#ifdef WITH_DAEMON
  if(daemon_fl) {
    syslog_log_init();
    if(daemon_init()<0){
      ul_logerr("daemonize failed\n");
      exit(2);
    }
  }else{
    if(syslog_fl)
      syslog_log_init();
  }
#endif /*WITH_DAEMON*/

  if(umask_set>=0) {
    umask(umask_set);
  }

  if(!inetd_fl){
    res=server_kyoscand(kyoscand_port_number, &kyoscan_app_options);
    if(res<0){
      ul_logerr("cannot start server\n");
      exit(3);
    }
  }else{
    res=inetd_kyoscan(&kyoscan_app_options);
    if(res<0){
      ul_logerr("communication failed\n");
      exit(3);
    }
  }

  return 0;
}
