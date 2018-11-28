/*
  ulog-dbacctd

  (C) 2002 Hilko Bengen
  (c) 2007 Igor Golubev
*/

int db_connect(void);
void db_disconnect(void);
int db_query(const char*);
char *db_error(void);
int db_checkconnect(void);
int db_select(const char *q);
int db_fetchrow(char **arr);
void db_endselect(void);
