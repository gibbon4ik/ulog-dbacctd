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

   Database procedures

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "config.h"

#ifdef POSTGRES
#include <libpq-fe.h>
#endif

#ifdef MY
#include <mysql.h>
#endif

extern struct config *cfg;

#ifdef POSTGRES

static PGconn *conn;
static PGresult *pgresult=NULL;
static int pgcurrow=0;

int db_pgconnect(void)
{
	char conninfo[512];
	char tmpbuff[128];

	snprintf(conninfo,511,"host=%s dbname=%s",cfg->dbhost,cfg->dbbase);
	if(cfg->dbport) {
		snprintf(tmpbuff,127," pgport=%s",cfg->dbport);
		strcat(conninfo,tmpbuff);
	}
	if(cfg->dbuser) {
		snprintf(tmpbuff,127," user=%s",cfg->dbuser);
		strcat(conninfo,tmpbuff);
	}
	if(cfg->dbpassword) {
		snprintf(tmpbuff,127," password=%s",cfg->dbpassword);
		strcat(conninfo,tmpbuff);
	}

	conn = PQconnectdb(conninfo);

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(conn) != CONNECTION_OK) {
		PQfinish(conn);	
		return 1;
	}
	pgresult=NULL;
	return 0;
}

void db_pgdisconnect(void)
{
	if(pgresult) PQclear(pgresult);
	PQfinish(conn);
}

int db_pgquery(const char *q)
{
	PGresult *res;
	res=PQexec(conn,q);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) 
	{
		PQclear(res);
		return 1;
	}
	PQclear(res);      
	return 0;
}

int db_pgselect(const char *q)
{
	pgresult=PQexec(conn,q);
	if (PQresultStatus(pgresult) != PGRES_TUPLES_OK) 
	{
		PQclear(pgresult);
		return 1;
	}
	pgcurrow=0;
	return 0;
}

void db_pgendselect(void)
{
	if(pgresult) PQclear(pgresult);
}

int db_pgfetchrow(char **arr)
{
	int i;
	if(pgcurrow >= PQntuples(pgresult)) return -1;
	for(i = 0;i < PQnfields(pgresult); i++) 
		arr[i]=PQgetvalue(pgresult,pgcurrow,i);
	pgcurrow++;
	return PQnfields(pgresult);
}

const char *db_pgerror(void)
{
	return PQerrorMessage(conn);
}

int db_pgcheckconnect(void)
{
	PGresult *res;
	res=PQexec(conn,"SELECT 1");
	PQclear(res);      
	if(PQstatus(conn)==CONNECTION_OK) return 0;
	return 1;
}

#endif

#ifdef MY

static MYSQL mysql;
static MYSQL_RES *mysql_res;

int db_myconnect(void)
{
	int port=0;
	if(cfg->dbport) port=atoi(cfg->dbport);
	if(!mysql_init(&mysql)) return 1;
	if(!mysql_real_connect(&mysql,cfg->dbhost,cfg->dbuser,
				cfg->dbpassword,cfg->dbbase,port,NULL,0)) return 1;
	return 0; 
}

void db_mydisconnect(void)
{
	mysql_close(&mysql);
}

int db_myquery(const char *q)
{
	return mysql_query(&mysql,q);
}

const char * db_myerror(void)
{
	return mysql_error(&mysql);
}

int db_mycheckconnect(void)
{
	return mysql_ping(&mysql);
}

int db_myselect(const char *q)
{
	if(mysql_query(&mysql,q)) return 1;
	mysql_res=mysql_store_result(&mysql);
	return 0;
}

int db_myfetchrow(char **arr)
{
	MYSQL_ROW row;
	int i;
	row=mysql_fetch_row(mysql_res);
	if(row==NULL) return -1;
	for(i=0; i<mysql_num_fields(mysql_res); i++) 
		arr[i]=row[i];
	return mysql_num_fields(mysql_res);
}

void db_myendselect(void)
{
	mysql_free_result(mysql_res);
}

#endif

int db_connect(void)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgconnect();
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myconnect();
#endif
	return 1;
}

void db_disconnect(void)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) db_pgdisconnect();
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) db_mydisconnect();
#endif
}

int db_query(const char *q)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgquery(q);
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myquery(q);
#endif
	return 1;
}

const char *db_error(void)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgerror();
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myerror();
#endif
	return "Not supported database type";
}

int db_checkconnect(void)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgcheckconnect();
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_mycheckconnect();
#endif
	return 1;

}


int db_select(const char *q)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgselect(q);
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myselect(q);
#endif
	return 1;
}

int db_fetchrow(char **arr)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgfetchrow(arr);
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myfetchrow(arr);
#endif
	return -1;
}

void db_endselect(void)
{
#ifdef POSTGRES
	if(cfg->dbtype==DBPGSQL) return db_pgendselect();
#endif
#ifdef MY
	if(cfg->dbtype==DBMYSQL) return db_myendselect();
#endif
}
