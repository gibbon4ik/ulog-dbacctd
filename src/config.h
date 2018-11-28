/*
  ulog-dbacctd

  (C) 2002 Hilko Bengen

  $Id: config.h,v 1.13 2004/04/06 08:49:35 bengen Exp $
*/

typedef enum {DBPGSQL,DBMYSQL} dbtypes;

struct config
{
  char *dbg_file;
  char *pid_file;
  char *lock_file;
  char *backup_file;
  char *acct_format;
  char *date_format;
  char *iphash_query;
  int flush; /* in seconds */
  int fdelay; /* in seconds */
  int err_delay; /* how many cycles to delay on error ? */
  int mcast_group;
  int output, debug; /* bitmasks */
  size_t so_rcvbuf;
  size_t hash_table_size;
  unsigned int hash_mask;
  unsigned int hash_initval;
  int logger_nice_value;
  char empty_iface[32];
  char empty_prefix[32];
  char *dbhost,*dbport,*dbbase,*dbuser,*dbpassword;
  dbtypes dbtype;
  short int dbtransaction;
  size_t iphash_table_size;
  unsigned int iphash_mask;
};

extern struct config *cfg; 

extern int dbg_file;

extern char *fname;

extern int db_connected;

#define DEFAULT_CONFFILE "/etc/ulog-dbacctd.conf"
#define DEFAULT_DATEFORMAT "%d/%m/%y %H:%M:%S"

/* default settings for naccttab */
#define DEFAULT_FLUSH 300
#define DEFAULT_ERR_DELAY 3
#define DEFAULT_FDELAY 60

#define FORCE_STAT_TIME 5

#define VERSION "0.4.1"

/* config.c */
struct config *read_config(char *fname);
