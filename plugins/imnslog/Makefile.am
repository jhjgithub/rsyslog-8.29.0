pkglib_LTLIBRARIES = imnslog.la
imnslog_la_SOURCES = imnslog.c bsd.c imnslog.h

imnslog_la_CPPFLAGS = -I$(top_srcdir) $(PTHREADS_CFLAGS) $(RSRT_CFLAGS) $(LIBLOGGING_STDLOG_CFLAGS)
imnslog_la_LDFLAGS = -module -avoid-version $(LIBLOGGING_STDLOG_LIBS)
imnslog_la_LIBADD = 
