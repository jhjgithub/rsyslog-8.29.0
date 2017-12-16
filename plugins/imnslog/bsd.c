#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/klog.h>
#include <sys/mman.h>

#include "rsyslog.h"
#include "srUtils.h"
#include "debug.h"
#include "imnslog.h"

#include "log.h"
//#include "logdev.h"

/* globals */
typedef struct nslog_data_s {
	int			 fd_nslog;
	nslog_ring_t *ring_addr;
	uint32_t 	 ring_size;

} nslog_data_t;

nslog_data_t g_nslog = { -1, NULL, 0} ;

#define _PATH_NSLOG "/dev/netshield/nslog"


static void
submitSyslog(modConfData_t *pModConf, syslog_pri_t pri, uchar *buf)
{
	long secs;
	long usecs;
	long secOffs;
	long usecOffs;
	unsigned i;
	unsigned bufsize;
	struct timespec monotonic, realtime;
	struct timeval tv;
	struct timeval *tp = NULL;

	if(!pModConf->bParseKernelStamp)
		goto done;

	if(buf[3] != '[')
		goto done;

	DBGPRINTF("imnslog: kernel timestamp detected, extracting it\n");

	/* we now try to parse the timestamp. iff it parses, we assume
	 * it is a timestamp. Otherwise we know for sure it is no ts ;)
	 */
	i = 4; /* space or first digit after '[' */
	while(buf[i] && isspace(buf[i]))
		++i; /* skip space */
	secs = 0;
	while(buf[i] && isdigit(buf[i])) {
		secs = secs * 10 + buf[i] - '0';
		++i;
	}
	if(buf[i] != '.') {
		DBGPRINTF("no dot --> no kernel timestamp\n");
		goto done; /* no TS! */
	}
	
	++i; /* skip dot */
	usecs = 0;
	while(buf[i] && isdigit(buf[i])) {
		usecs = usecs * 10 + buf[i] - '0';
		++i;
	}
	if(buf[i] != ']') {
		DBGPRINTF("no trailing ']' --> no kernel timestamp\n");
		goto done; /* no TS! */
	}
	++i; /* skip ']' */

	/* we have a timestamp */
	DBGPRINTF("kernel timestamp is %ld %ld\n", secs, usecs);
	if(!pModConf->bKeepKernelStamp) {
		bufsize= strlen((char*)buf);
		memmove(buf+3, buf+i, bufsize - i + 1);
	}

	clock_gettime(CLOCK_MONOTONIC, &monotonic);
	clock_gettime(CLOCK_REALTIME, &realtime);
	secOffs = realtime.tv_sec - monotonic.tv_sec;
	usecOffs = (realtime.tv_nsec - monotonic.tv_nsec) / 1000;
	if(usecOffs < 0) {
		secOffs--;
		usecOffs += 1000000l;
	}
	
	usecs += usecOffs;
	if(usecs > 999999l) {
		secs++;
		usecs -= 1000000l;
	}
	secs += secOffs;
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	tp = &tv;

done:
	nslog_syslog(pModConf, pri, buf, tp);
}

static uchar *GetPath(modConfData_t *pModConf)
{
	return pModConf->pszPath ? pModConf->pszPath : (uchar*) _PATH_NSLOG;
}

/* open the kernel log - will be called inside the willRun() imnslog
 * entry point. -- rgerhards, 2008-04-09
 */
rsRetVal
nslog_WillRunPrePrivDrop(modConfData_t *pModConf)
{
	char errmsg[2048];

	//nslog_ring_t *logring;
	//char *addr;
	DEFiRet;

#if 0
	g_nslog.fd_nslog = open((char*)GetPath(pModConf), O_RDONLY, 0);
	if (g_nslog.fd_nslog < 0) {
		imnslogLogIntMsg(LOG_ERR, "imnslog: cannot open kernel log (%s): %s.",
						 GetPath(pModConf), rs_strerror_r(errno, errmsg, sizeof(errmsg)));
		ABORT_FINALIZE(RS_RET_ERR_OPEN_KLOG);
	}

	g_nslog.ring_size = 4096 * 3;

	addr = mmap(NULL, g_nslog.ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_nslog.fd_nslog, 0);
	if (addr == MAP_FAILED) {
		imnslogLogIntMsg(LOG_ERR, "imnslog: cannot alloc NetShield LOG Ring (%s)", GetPath(pModConf));
		ABORT_FINALIZE(RS_RET_ERR_OPEN_NSLOG);
	}

	logring = (nslog_ring_t*)addr;

	imnslogLogIntMsg(LOG_INFO, "NSLOG Ring: Magic: 0x%x, Version: 0x%x, Ring Count: %d, Slog Size: %d", 
					 logring->magic, logring->ver, logring->cnt, logring->slot_size);

	g_nslog.ring_addr = logring;
#endif

	/* Set level of kernel console messaging.. */
	if(pModConf->console_log_level != -1) {
		int r = klogctl(8, NULL, pModConf->console_log_level);
		if(r != 0) {
			imnslogLogIntMsg(LOG_WARNING, "imnslog: cannot set console log level: %s",
							 rs_strerror_r(errno, errmsg, sizeof(errmsg)));
			/* make sure we do not try to re-set! */
			pModConf->console_log_level = -1;
		}
	}

//finalize_it:
	RETiRet;
}

/* make sure the kernel log is readable after dropping privileges
 */
rsRetVal
nslog_WillRunPostPrivDrop(modConfData_t *pModConf)
{
#if 0
	char errmsg[2048];
	int r;
	DEFiRet;

	/* this normally returns EINVAL */
	/* on an OpenVZ VM, we get EPERM */
	r = read(g_nslog.fd_nslog, NULL, 0);
	if (r < 0 && errno != EINVAL) {
		imnslogLogIntMsg(LOG_ERR, "imnslog: cannot open kernel log (%s): %s.",
			GetPath(pModConf), rs_strerror_r(errno, errmsg, sizeof(errmsg)));
		g_nslog.fd_nslog = -1;
		ABORT_FINALIZE(RS_RET_ERR_OPEN_KLOG);
	}

finalize_it:
	RETiRet;
#else
	return RS_RET_OK;
#endif

}


#if 0
/* Read kernel log while data are available, split into lines.
 */
static void
read_nslog_org(modConfData_t *pModConf)
{
	char *p, *q;
	int len, i;
	int iMaxLine;
	uchar bufRcv[128*1024+1];
	char errmsg[2048];
	uchar *pRcv = NULL; /* receive buffer */

	iMaxLine = nslog_getMaxLine();

	/* we optimize performance: if iMaxLine is below our fixed size buffer (which
	 * usually is sufficiently large), we use this buffer. if it is higher, heap memory
	 * is used. We could use alloca() to achive a similar aspect, but there are so
	 * many issues with alloca() that I do not want to take that route.
	 * rgerhards, 2008-09-02
	 */
	if((size_t) iMaxLine < sizeof(bufRcv) - 1) {
		pRcv = bufRcv;
	} else {
		if((pRcv = (uchar*) MALLOC(iMaxLine + 1)) == NULL) {
			iMaxLine = sizeof(bufRcv) - 1; /* better this than noting */
			pRcv = bufRcv;
		}
	}

	len = 0;
	for (;;) {
		dbgprintf("imnslog(BSD/Linux) waiting for kernel log line\n");
		i = read(g_nslog.fd_nslog, pRcv + len, iMaxLine - len);
		if (i > 0) {
			pRcv[i + len] = '\0';
		} else {
			if (i < 0 && errno != EINTR && errno != EAGAIN) {
				imnslogLogIntMsg(LOG_ERR,
								 "imnslog: error reading kernel log - shutting down: %s",
								 rs_strerror_r(errno, errmsg, sizeof(errmsg)));
				g_nslog.fd_nslog = -1;
			}
			break;
		}

		for (p = (char*)pRcv; (q = strchr(p, '\n')) != NULL; p = q + 1) {
			*q = '\0';
			submitSyslog(pModConf, LOG_INFO, (uchar*) p);
		}
		len = strlen(p);
		if (len >= iMaxLine - 1) {
			submitSyslog(pModConf, LOG_INFO, (uchar*)p);
			len = 0;
		}
		if(len > 0)
			memmove(pRcv, p, len + 1);
	}
	if (len > 0)
		submitSyslog(pModConf, LOG_INFO, pRcv);

	if(pRcv != bufRcv)
		free(pRcv);
}
#endif

static void
read_nslog(modConfData_t *pModConf)
{
	nslog_status_t rinfo;
	nslog_ring_t *logring = NULL;
	int len, i;
	int iMaxLine;
	uchar bufRcv[128*1024+1];
	char errmsg[2048];
	uchar *pRcv = NULL; /* receive buffer */
	nslog_t *base;
	char *addr;
	int fd_nslog = -1;

	g_nslog.ring_size = 4096 * 3;
	iMaxLine = nslog_getMaxLine();

	/* we optimize performance: if iMaxLine is below our fixed size buffer (which
	 * usually is sufficiently large), we use this buffer. if it is higher, heap memory
	 * is used. We could use alloca() to achive a similar aspect, but there are so
	 * many issues with alloca() that I do not want to take that route.
	 * rgerhards, 2008-09-02
	 */
	if ((size_t) iMaxLine < sizeof(bufRcv) - 1) {
		pRcv = bufRcv;
	} 
	else {
		if ((pRcv = (uchar*) MALLOC(iMaxLine + 1)) == NULL) {
			iMaxLine = sizeof(bufRcv) - 1; /* better this than noting */
			pRcv = bufRcv;
		}
	}

START:
	while (fd_nslog == -1) {
		fd_nslog = open((char*)GetPath(pModConf), O_RDONLY, O_SYNC);
		//fd_nslog = open(_PATH_NSLOG, O_RDWR, O_SYNC);
		//fd = open(dev_name, O_RDWR | O_SYNC); 

		if (fd_nslog < 0) {
			imnslogLogIntMsg(LOG_ERR, "imnslog: cannot open NetShield kernel log (%s): %s.",
							 GetPath(pModConf), rs_strerror_r(errno, errmsg, sizeof(errmsg)));
			//ABORT_FINALIZE(RS_RET_ERR_OPEN_KLOG);
			sleep(1);
			continue;
		}

		//addr = mmap(NULL, g_nslog.ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_nslog, 0);
		addr = mmap(NULL, g_nslog.ring_size, PROT_READ, MAP_SHARED, fd_nslog, 0);
		if (addr == MAP_FAILED) {
			imnslogLogIntMsg(LOG_ERR, "imnslog: cannot alloc NetShield LOG Ring (%s)", GetPath(pModConf));
			close(fd_nslog);
			fd_nslog = -1;
			//ABORT_FINALIZE(RS_RET_ERR_OPEN_NSLOG);
			sleep(1);
			continue;
		}

		logring = (nslog_ring_t*)addr;

		imnslogLogIntMsg(LOG_ERR, "NSLOG Ring: Magic: 0x%x, Version: 0x%x, Ring Count: %d, Slog Size: %d", 
						 logring->magic, logring->ver, logring->cnt, logring->slot_size);

		g_nslog.fd_nslog = fd_nslog;
		g_nslog.ring_addr = logring;
	}

	len = 0;
	base = (nslog_t*)logring->data;

	while (1) {
		memset(&rinfo, 0, sizeof(nslog_status_t));

		len = read(g_nslog.fd_nslog, (void*)&rinfo, sizeof(nslog_status_t));
		if (len != sizeof(nslog_status_t)) {
			if (errno == EINTR || errno == EAGAIN) {
				imnslogLogIntMsg(LOG_ERR,
								 "imnslog: error reading NetShield kernel log - retry: %s",
								 rs_strerror_r(errno, errmsg, sizeof(errmsg)));

				sleep(1);
			}
			else if (errno == ENOSPC) {
				imnslogLogIntMsg(LOG_ERR,
								 "imnslog: Stopped NetShield kernel log - shutting down: %s",
								 rs_strerror_r(errno, errmsg, sizeof(errmsg)));

				break;
			}
			else {
				if (g_nslog.ring_addr) {
					munmap(g_nslog.ring_addr, g_nslog.ring_size);
					g_nslog.ring_addr = NULL;
				}

				if (g_nslog.fd_nslog != -1) {
					close(g_nslog.fd_nslog);
					g_nslog.fd_nslog = -1;
					fd_nslog = -1;
				}

				goto START;
			}

			continue;
		}

		imnslogLogIntMsg(LOG_ERR, "Read len=%d, start=%d, cnt=%d", len, rinfo.start, rinfo.cnt);

		for (i=0; i<rinfo.cnt; i++) {
			nslog_t *log;
			int idx = (rinfo.start + i) % logring->cnt;
			log = &base[idx];

			sprintf((char*)pRcv, "log date[%d]=%lu:%s", idx, log->date, log->msg);

			imnslogLogIntMsg(LOG_ERR, "%s", bufRcv);
			submitSyslog(pModConf, LOG_INFO, bufRcv);
		}

		logring->tail = (logring->tail + rinfo.cnt) % logring->cnt;
	}

	imnslogLogIntMsg(LOG_ERR, "imnslog: Stop NetShield kernel log");

	if (pRcv != bufRcv)
		free(pRcv);
} 
 

/* to be called in the module's AfterRun entry point
 * rgerhards, 2008-04-09
 */
rsRetVal nslog_AfterRun(modConfData_t *pModConf)
{
	DEFiRet;

	if (g_nslog.ring_addr) {
		munmap(g_nslog.ring_addr, g_nslog.ring_size);
	}

	if (g_nslog.fd_nslog != -1)
		close(g_nslog.fd_nslog);

	/* Turn on logging of messages to console, but only if a log level was speficied */
	if (pModConf->console_log_level != -1)
		klogctl(7, NULL, 0);

	RETiRet;
}

/* to be called in the module's WillRun entry point, this is the main
 * "message pull" mechanism.
 * rgerhards, 2008-04-09
 */
rsRetVal nslog_main(modConfData_t *pModConf)
{
	DEFiRet;
	read_nslog(pModConf);
	RETiRet;
}


/* provide the (system-specific) default facility for internal messages
 * rgerhards, 2008-04-14
 */
int
nslog_FacilIntMsg(void)
{
	return LOG_SYSLOG;
}
