/*
   ulog-dbacctd --- a network accounting daemon for Linux
   Copyright (C) 2002, 2003 Hilko Bengen
   Copyright (C) 2007 Igor Golubev    
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


 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <arpa/inet.h>

struct iphash {
	u_int32_t ip,mask;
	int value;
	struct iphash *next;
};

int iph_init(void);
void iph_free(void);
int iph_clear(void);
int iph_add(u_int32_t ip,u_int32_t mask, int value);
int iph_search(u_int32_t ip);
u_int32_t ip2uint(u_int8_t a,u_int8_t b,u_int8_t c,u_int8_t d);
void iph_printstruct(void);
int iph_aton(const char *s,u_int32_t *ip,u_int32_t *mask);

/* extern struct iphash **iphlist;
 */
