#include "user_table.h"

#include <string.h>

struct user_entry {
  char name[MAX_CRED_LEN + 1];
  char pass[MAX_CRED_LEN + 1];
  bool active;
};

static struct {
  struct user_entry entries[MAX_USERS];
  unsigned count;
} table;

void user_table_init(void) { memset(&table, 0, sizeof(table)); }

static struct user_entry *find_by_name(const char *name) {
  for (unsigned i = 0; i < MAX_USERS; i++) {
    if (table.entries[i].active && strcmp(table.entries[i].name, name) == 0)
      return &table.entries[i];
  }
  return NULL;
}

bool user_table_add(const char *name, const char *pass) {
  if (name == NULL || pass == NULL) return false;
  size_t nlen = strlen(name), plen = strlen(pass);
  if (nlen == 0 || nlen > MAX_CRED_LEN) return false;
  if (plen == 0 || plen > MAX_CRED_LEN) return false;
  if (find_by_name(name) != NULL) return false;
  if (table.count >= MAX_USERS) return false;

  for (unsigned i = 0; i < MAX_USERS; i++) {
    if (!table.entries[i].active) {
      strncpy(table.entries[i].name, name, MAX_CRED_LEN);
      table.entries[i].name[MAX_CRED_LEN] = '\0';
      strncpy(table.entries[i].pass, pass, MAX_CRED_LEN);
      table.entries[i].pass[MAX_CRED_LEN] = '\0';
      table.entries[i].active = true;
      table.count++;
      return true;
    }
  }
  return false;
}

bool user_table_remove(const char *name) {
  struct user_entry *e = find_by_name(name);
  if (e == NULL) return false;
  e->active = false;
  table.count--;
  return true;
}

bool user_table_lookup(const char *name, const char *pass) {
  struct user_entry *e = find_by_name(name);
  if (e == NULL) return false;
  return strcmp(e->pass, pass) == 0;
}

unsigned user_table_count(void) { return table.count; }

void user_table_list(user_list_cb_t cb, void *ctx) {
  for (unsigned i = 0; i < MAX_USERS; i++) {
    if (table.entries[i].active) cb(table.entries[i].name, ctx);
  }
}
