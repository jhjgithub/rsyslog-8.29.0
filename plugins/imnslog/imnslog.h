/* imnslog.h
 * copied from imklog.h
 */
#ifndef	IMNSLOG_H_INCLUDED
#define	IMNSLOG_H_INCLUDED 1

#include "rsyslog.h"
#include "dirty.h"

/* we need to have the modConf type present in all submodules */
struct modConfData_s {
	rsconf_t *pConf;
	int iFacilIntMsg;
	uchar *pszPath;
	int console_log_level;
	sbool bParseKernelStamp;
	sbool bKeepKernelStamp;
	sbool bPermitNonKernel;
	sbool configSetViaV2Method;
};

/* interface to "drivers"
 * the platform specific drivers must implement these entry points. Only one
 * driver may be active at any given time, thus we simply rely on the linker
 * to resolve the addresses.
 * rgerhards, 2008-04-09
 */
rsRetVal nslog_main(modConfData_t *pModConf);
rsRetVal nslog_AfterRun(modConfData_t *pModConf);
rsRetVal nslog_WillRunPrePrivDrop(modConfData_t *pModConf);
rsRetVal nslog_WillRunPostPrivDrop(modConfData_t *pModConf);
int 	 nslog_FacilIntMsg(void);

/* the functions below may be called by the drivers */
rsRetVal imnslogLogIntMsg(syslog_pri_t priority, const char *fmt, ...) __attribute__((format(printf,2, 3)));
rsRetVal nslog_syslog(modConfData_t *pModConf, syslog_pri_t priority, uchar *msg, struct timeval *tp);

/* prototypes */
extern int nslog_getMaxLine(void); /* work-around for klog drivers to get configured max line size */

#if 0
extern int InitKsyms(modConfData_t*);
extern void DeinitKsyms(void);
extern int InitMsyms(void);
extern void DeinitMsyms(void);
extern char * ExpandKadds(char *, char *);
extern void SetParanoiaLevel(int);
#endif

#endif /* #ifndef IMNSLOG_H_INCLUDED */
