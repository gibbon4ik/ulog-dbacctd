/*
  ulog-dbacctd --- a network accounting daemon for Linux
  Copyright (C) 2002, 2003 Hilko Bengen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


  Main module

  $Id: main.c,v 1.12 2003/09/29 11:58:13 bengen Exp $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <syslog.h>
#include <errno.h>

#include "config.h"
#include "daemon.h"
#include "process.h"
#include "capture.h"
#include "dbase.h"
#include "iphash.h"

/* globals */
char *progname;
struct config *cfg;
volatile int debug_level;
struct dev2line *dev2line;
int dbg_file;

char *fname = NULL;
static int debug = 0;
static int daem = 1;

void usage(void)
{
  fprintf(stderr, "Usage: %s [-dD] [-c filename]\n\n\t-d\tSwitch on debugging\n", progname);
  fprintf(stderr, "\t-c\tSpecify alternative configuration file\n");
  fprintf(stderr, "\t-D\tDon't detach (for inittab)\n\n");
}

void process_options(int argc, char *argv[])
{
  int c;

  fname = strdup(DEFAULT_CONFFILE);
   
  while ((c = getopt( argc, argv, "c:dD" )) != EOF)
    {
      switch (c)
	{
	case 'c':
	  free(fname);
	  fname = strdup(optarg);
	  break;
	case 'd':
	  debug = 1;
	  break;
	case 'D':
	  daem = 0;
	  break;
	case '?':
	default:
	  usage();
	  exit(1);
	}
    }
   
  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      usage();
      exit(1);
    }
}

int do_pid_file(void)
     /* return 1 if file could be created */
     /* return 0 if daemon already running */
     /* this is by no means clean of races, if we take it serious we should do it with
	some well thought out atomic operations */
{
  FILE *f;

  if(access(cfg->pid_file,F_OK)==0)
    {
      char buff[80];
      int pid;
      /* file exists */

      f = fopen(cfg->pid_file, "r");
      fgets(buff, sizeof(buff), f);
      fclose(f);

      pid = atoi(buff);

      syslog(LOG_INFO, "found pid-file with pid %d", pid);

      if(kill(pid, 0) == -1)
	{
	  syslog(LOG_INFO, "process %d doesn't exist anymore", pid);
	}
      else
	{
	  syslog(LOG_INFO, "process %d is still running.", pid);
	  return 0;
	}

    }

  f = fopen(cfg->pid_file, "w");
  if (f)
    {
      fprintf(f, "%d\n", (int) getpid());
      fclose(f);
    }
  else
    syslog(LOG_INFO, "Could not write PID file %s: %m",cfg->pid_file);
    
  return 1;
}


/* Set a signal handler. */
#define SETSIG(sig, fun, fla)   sa.sa_handler = fun; \
                                sa.sa_flags = fla; \
                                sigaction(sig, &sa, NULL);

void signal_setup(void)
{
  struct sigaction sa;

  /* these stop the program */
  SETSIG(SIGINT, daemon_stop, 0);
  SETSIG(SIGTERM, daemon_stop, 0);
    
  /* this one does the scheduling of write processes and handles the internal clock */
  SETSIG(SIGALRM, alarm_handler, 0);
    
  /* handles notification about child exits */
  SETSIG(SIGCHLD, child_finished, 0);

  /* the following signals are used in a nonstandard sense */

  /* in case the program stops receiving packets (due to a kernel bug) */
  SETSIG(SIGIOT, signal_debug, 0); /* reopen socket */

  /* to cleanly move logfiles */
  SETSIG(SIGUSR1, signal_debug, 0); /* writing statistic */
  SETSIG(SIGUSR2, signal_debug, 0); /* writing statistic full */

  /* reread configuration */
  SETSIG(SIGHUP, signal_debug, 0);
}

int main(int argc, char *argv[])
{
  progname = argv[0];
  
  if(geteuid() != 0)
    {
      syslog(LOG_ERR, "must be superuser to run ulog-dbacctd");
      exit(1);
    }

  /* process user options */
  process_options(argc, argv);

  openlog("ulog-dbacctd", LOG_PID, LOG_DAEMON);
  syslog(LOG_INFO, "ulog-dbacctd net accounting daemon v"VERSION" started");

  /* read config file */
  cfg = read_config(fname);
  if(cfg == NULL)
    {
      syslog(LOG_ERR, "error reading config file");
      syslog(LOG_INFO, "net accounting daemon aborting");
      exit(1);
    }



  if(!debug && daem)
    {
      /* start daemon */
      if(daemon_start()!=-1)
	{
	  openlog("ulog-dbacctd", LOG_PID, LOG_DAEMON);
	  syslog(LOG_INFO, "net accounting daemon forked");
	}
      else
	{
	  syslog(LOG_ERR, "couldn't fork: %m");
	  syslog(LOG_INFO, "net accounting daemon aborting");
	  exit(1);
	}
    }

  if( cfg->dbg_file != NULL ) 
    {
      dbg_file = open(cfg->dbg_file, O_WRONLY|O_CREAT|O_APPEND, 0644);
      if(dbg_file==-1)
	{
	  syslog(LOG_ERR, "error opening debug file: %m");
	  syslog(LOG_INFO, "net accounting daemon aborting");
	  exit(1);
	}
    }
  else
    {
      dbg_file=STDERR_FILENO;
    }



  /* check and create /var/run/ulog-dbacctd.pid */
  if(!do_pid_file())
    {
      syslog(LOG_ERR, "daemon already running or stale pid-file");
      exit(1);
    }

  if (db_connect()) {
	syslog(LOG_ERR, "Connection to database failed");
	db_connected=0;
	}
  else {
	db_connected=1;
	}

  iph_init();

  /* signal setup */
  signal_setup();

  /* init capturing */
  init_capture();
    
  /* start being useful */
  do_acct();

  close(dbg_file);
  iph_free();
  db_disconnect();
  return 0;
}
