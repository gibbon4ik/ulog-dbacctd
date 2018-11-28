/*
  ulog-dbacctd

  (C) 2002 Hilko Bengen

  $Id: daemon.h,v 1.2 2002/12/14 06:29:27 bengen Exp $
*/

/* daemon.c */
int daemon_start(void);
void daemon_stop(int sig);

