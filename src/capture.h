/*
  ulog-dbacctd

  (C) 2002 Hilko Bengen

  $Id: capture.h,v 1.1 2002/09/26 11:59:47 bengen Exp $
*/

/* capture.c */
void init_capture(void);
void do_acct(void);
void exit_capture(void);
void packet_loop(void);
