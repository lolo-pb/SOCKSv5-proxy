#ifndef USER_TABLE_H
#define USER_TABLE_H

#include <stdbool.h>

#define MAX_USERS 10
#define MAX_CRED_LEN 255

void user_table_init(void);
bool user_table_add(const char *name, const char *pass);
bool user_table_remove(const char *name);
bool user_table_lookup(const char *name, const char *pass);
unsigned user_table_count(void);

typedef void (*user_list_cb_t)(const char *name, void *ctx);
void user_table_list(user_list_cb_t cb, void *ctx);

#endif
