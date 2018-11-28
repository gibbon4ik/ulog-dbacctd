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
#include <stdlib.h>
#include <string.h>
#include "iphash.h"
#include "config.h"

static u_int32_t masks[33];

struct iphash **iphlist = NULL;
struct iphash *ipnhlist = NULL;

int IPHASH(u_int32_t x)
{
	return ((x)+(x>>8)) & cfg->iphash_mask;
}

int iph_init(void)
{
	int i;
	u_int32_t mask = ~0U;
	for (i = 32; i>=0; i--) {
		masks[i]=htonl(mask);
		mask = mask<<1;
	}

	iphlist=malloc(cfg->iphash_table_size*sizeof(struct iphash));
	if (!iphlist) return 1;

	for (i = 0; i < cfg->iphash_table_size; i++) iphlist[i] = NULL;
	ipnhlist = NULL;
	return 0;
}

void iph_free(void)
{
	iph_clear();
	free(iphlist);
}

int iph_clear(void)
{
	int i;
	struct iphash *p,*n;
	p = ipnhlist;
	while(p) {
		n = p->next;
		free(p);
		p = n;
	}
	ipnhlist = NULL;

	if(!iphlist) return 0;

	for(i = 0;i < cfg->iphash_table_size; i++) {
		p = iphlist[i];
		while(p) {
			n = p->next;
			free(p);
			p = n;
		}
		iphlist[i] = NULL;
	}
	return 0;
}

int iph_add(u_int32_t ip,u_int32_t mask, int value)
{
	int i;
	struct iphash *p;
	p = malloc(sizeof(struct iphash));
	if(p==NULL) return 1;
	p->ip = ip;
	p->mask = mask;
	p->value = value;

	if(mask==0xffffffffU) {
		i = IPHASH(ip);
		p->next = iphlist[i];
		iphlist[i]=p;
	}
	else {
		p->next = ipnhlist;
		ipnhlist = p; 
	}
	return 0;
}

int iph_search(u_int32_t ip)
{
	int i;
	struct iphash *p;
	i = IPHASH(ip);
	p=iphlist[i];
	while(p) {
		if( ip == p->ip) return p->value;
		p=p->next;
	}
	p=ipnhlist;
	while(p) {
		if( (ip & p->mask) == p->ip) return p->value;
		p=p->next;
	}
	return -1;
}

u_int32_t ip2uint(u_int8_t a,u_int8_t b,u_int8_t c,u_int8_t d)
{
	return htonl(a<<24 | b<<16 | c<<8 | d);
}

void iph_printstruct(void)
{
	int i;
	struct iphash *p;
	for(i=0;i<cfg->iphash_table_size;i++) {
		p=iphlist[i];
		printf("%d:",i);
		while(p) {
			printf("ip=%X mask=%X val=%d, ",p->ip,p->mask,p->value);
			p=p->next;
		}
		printf("\n");
	}
}

int iph_aton(const char *s,u_int32_t *ip,u_int32_t *mask)
{
	unsigned int a,b,c,d;
	char *smask,ipbuf[16];

	*ip=0;
	*mask=0xFFFFFFFF;

	smask=strchr(s,'/');
	if(smask) {
		smask++;
		if(strchr(smask,'.')) {
			if(sscanf(smask,"%3u.%3u.%3u.%3u",&a,&b,&c,&d)!=4) return 1;
			if(a>255 || b>255 || c>255 || d>255) return 1;
			*mask=ip2uint(a,b,c,d);
		}
		else {
			if(sscanf(smask,"%2u",&a)!=1) return 1;
			if(a>32) return 1;
			*mask=masks[a];
		}
	}
	strncpy(ipbuf,s,15);
	smask=strchr(ipbuf,'/');
	if(smask) *smask='\0';
	if(sscanf(ipbuf,"%3u.%3u.%3u.%3u",&a,&b,&c,&d)!=4) return 1;
	if(a>255 || b>255 || c>255 || d>255) return 1;
	*ip=ip2uint(a,b,c,d)&*mask;
	return 0;
}

