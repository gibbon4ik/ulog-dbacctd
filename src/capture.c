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


  Packet capture module, Based on capture-linux.c from net-acctd
  
  $Id: capture.c,v 1.17 2003/08/22 16:52:30 bengen Exp $
*/

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "process.h"
#include "debug.h"
#include "config.h"
#include "daemon.h"
#include "capture.h"
#include "dbase.h"
#include "utils.h"

#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <fcntl.h>

#include <syslog.h>

/* For parsing netlink headers */
#include <linux/netlink.h>

/* For parsing ulog packets */
#include <linux/if.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

static int capture_sd = -1;

extern struct statistics* stats;

void init_capture()
{
  struct sockaddr_nl local_addr;

  /* open socket for ulog target */
  capture_sd=socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
  if (!capture_sd)
    {
      DEBUG(DBG_ERR, my_sprintf("can't create netlink socket: %m"));
      daemon_stop(0);
    }

  /* Set socket receive buffer size if requested. */
  if (cfg->so_rcvbuf)
    if (setsockopt(capture_sd, SOL_SOCKET, SO_RCVBUF, 
		   &(cfg->so_rcvbuf), sizeof(size_t)) < 0)
      {
	DEBUG(DBG_ERR, my_sprintf("can't set socket receive buffer to %d: %m",cfg->so_rcvbuf));
	daemon_stop(0);
      }

  /* bind socket to ULOG target */
  memset(&local_addr, 0, sizeof(struct sockaddr_nl));
  local_addr.nl_family=AF_NETLINK;
  local_addr.nl_pad=0;
  local_addr.nl_pid=getpid();
  local_addr.nl_groups=cfg->mcast_group;

  if (bind (capture_sd, (struct sockaddr*) &local_addr, sizeof(struct sockaddr_nl))<0)
    {
      DEBUG(DBG_ERR, my_sprintf("can't bind to netlink socket: %m"));
      daemon_stop(0);
    }
}

void exit_capture(void)
{
  close(capture_sd);
}

void packet_loop()
{
  /* sockaddr for recvfrom() call */
  struct sockaddr_nl saddr;
  socklen_t sizeaddr;

  /* This should be enough for IP headers. Increase and recompile if
     you get "Short packet" messages */
#define ULOG_COPY_RANGE 32
  /* Maximum size we will be able to read in one recvfrom() call
     below: ULOG_MAX_QLEN netlink messages, containing a netlink
     message header an ULOG packet header, plus ULOG_COPY_MESSAGE
     bytes  */
#define RECV_BUFSIZE ULOG_MAX_QLEN*((NLMSG_DATA(NULL)-NULL)+sizeof(struct ulog_packet_msg)+ULOG_COPY_RANGE)

  unsigned char buf[RECV_BUFSIZE];
  int length;

  /* For parsing netlink headers */
  int remaining_length;
  struct nlmsghdr * current_nlmsghdr, * last_nlmsghdr=NULL;

  /* For parsing ulog packets */
  struct ulog_packet_msg * ulog_packet;

  int ret;
  fd_set readfds;

  DEBUG(DBG_ANNOYING, my_sprintf("RECV_BUFSIZE: %i", RECV_BUFSIZE));
  while (running)
    {
      /* process signals */

      if( sigflag_force_write_log )
	{
	  if( write_log(1) == 0)
	    {
	      if (sigflag_force_write_log != 1)
		{
		  DEBUG(DBG_ERR, my_sprintf("signal_force_write_log = %d.",sigflag_force_write_log));
		}
	      sigflag_force_write_log--;
	    }
	  else
	    {
	      DEBUG(DBG_ERR, "Could not write accounting data.");
	    }
	}

      if( sigflag_write_log )
	{
	  if( write_log(0) == 0)
	    {
	      if (sigflag_write_log != 1)
		{
		  DEBUG(DBG_ERR, my_sprintf("signal_write_log = %d.",sigflag_write_log));
		}
	      sigflag_write_log--;
	    }
	  else
	    {
	      DEBUG(DBG_ERR, "Could not write accounting data.");
	    }
	}

      if( sigflag_reread_config )
	{
	  DEBUG(DBG_STATE, "re-reading config");
	  exit_capture();
	  write_log(1);

	  if(cfg) {
	    free(cfg->acct_format);
	    free(cfg->iphash_query);
	    free(cfg->date_format);
	    free(cfg->dbg_file);
	    free(cfg->pid_file);
	    free(cfg->dbhost);
	    free(cfg->dbport);
	    free(cfg->dbbase);
	    free(cfg->dbuser);
	    free(cfg->dbpassword);
	    free(cfg);
	  }
      
	  cfg = read_config(fname);
	  init_capture();
	  if (--sigflag_reread_config)
	    {
	      DEBUG(DBG_ERR, "sigflag_reread_config > 1");
	    }
	}

      if( sigflag_reopen_socket )
	{
	  DEBUG(DBG_STATE, "re-opening socket");
	  write_log(1);
	  reopen_socket();


	  if (sigflag_reopen_socket != 1)
	    {
	      DEBUG(DBG_ERR, my_sprintf("signal_reopen_socket = %d.", 
					sigflag_reopen_socket));
	    }
	  sigflag_reopen_socket--;
	}

      if (sigflag_child_finished) wait_children();

      /* Wait until data is available */
      FD_ZERO(&readfds);
      FD_SET(capture_sd,&readfds);
      ret=select(capture_sd+1,&readfds,NULL,NULL,NULL);
	if (ret<0)
	  {
	    if (errno!=EINTR) {
	      DEBUG(DBG_ERR, my_sprintf("select(): %m"));
	    }
	    continue;
	  }
	else if (ret>0)
	  {
	    sizeaddr=sizeof(struct sockaddr_nl);
	    
	    DEBUG(DBG_ANNOYING, "recvfrom()");
	    length = recvfrom (capture_sd, buf, RECV_BUFSIZE, 0, 
			       (struct sockaddr *) &saddr, &sizeaddr);
	    if (length == -1)
	      {
		switch (errno)
		  {
		  case EINTR: 
		    break;
		  default:
		    DEBUG(DBG_ERR, my_sprintf("recvfrom(): %m"));
		    stats->nl_recv_error++;
		  }
		DEBUG(DBG_ANNOYING, my_sprintf("recvfrom(): %m"));
		continue;
	      }
	    DEBUG(DBG_ANNOYING, my_sprintf("recvfrom(): %i",length));
	
	    /* FIXME: check for value of sizeaddr? */
	
	    /* Iterate over every packet the netlink message contains. Check
	       it and register it if necessary.  */
	    current_nlmsghdr=(struct nlmsghdr *) buf;
	    remaining_length=length;
	    do
	      {
		/* Check if the current netlink message is parseable. If
		   not, break out of the loop to receive the next netlink
		   message from the socket. We won't know how many IP packets
		   we lost this way, of course.
	       
		   This is only a length check, so we have to do it on every
		   message in the chain. */
		if (!NLMSG_OK( current_nlmsghdr, remaining_length))
		  {
		    DEBUG(DBG_ERR, "Truncated netlink message.");
		    stats->nl_truncated++;
		    break;
		  }
	    
		/* Get the ulog packet as defined in ipt_ULOG.h */
		ulog_packet=NLMSG_DATA(current_nlmsghdr);
	    
		/* If the host was not the packet's source or destination,
		   both ulog_packet->indev_name and ulog_packet->outdev_name
		   will be defined. */
	    
		register_packet((struct iphdr*) ulog_packet->payload, 
				ulog_packet->data_len,
				ulog_packet->indev_name, 
				ulog_packet->outdev_name, 
				ulog_packet->prefix,
				ulog_packet->mac_len,
				ulog_packet->mac);

		/* Go on to next header */
		last_nlmsghdr=current_nlmsghdr;
		current_nlmsghdr=NLMSG_NEXT(current_nlmsghdr, remaining_length);
	      } while ( (last_nlmsghdr->nlmsg_type != NLMSG_DONE) &&
			(last_nlmsghdr->nlmsg_flags & NLM_F_MULTI) );
	  }
    }
}
