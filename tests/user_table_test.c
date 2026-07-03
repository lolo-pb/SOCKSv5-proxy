#include <assert.h>
#include <stdio.h>

#include "user_table.c"

static int list_count;
static void count_cb(const char *name, void *ctx) {
  (void) name;
  (void) ctx;
  list_count++;
}

int main(void) {
  user_table_init();
  assert(user_table_count() == 0);

  assert(user_table_add("alice", "pass1"));
  assert(user_table_add("bob", "pass2"));
  assert(user_table_count() == 2);

  /* duplicate rejected */
  assert(!user_table_add("alice", "other"));

  /* lookup */
  assert(user_table_lookup("alice", "pass1"));
  assert(!user_table_lookup("alice", "wrong"));
  assert(!user_table_lookup("nobody", "x"));

  /* remove + re-add */
  assert(user_table_remove("alice"));
  assert(user_table_count() == 1);
  assert(!user_table_lookup("alice", "pass1"));
  assert(user_table_add("alice", "newpass"));
  assert(user_table_lookup("alice", "newpass"));

  /* list */
  list_count = 0;
  user_table_list(count_cb, NULL);
  assert(list_count == 2);

  /* fill to max */
  user_table_init();
  for (int i = 0; i < MAX_USERS; i++) {
    char name[8];
    snprintf(name, sizeof(name), "u%d", i);
    assert(user_table_add(name, "p"));
  }
  assert(!user_table_add("overflow", "p"));

  /* invalid inputs */
  assert(!user_table_add(NULL, "p"));
  assert(!user_table_add("x", NULL));
  assert(!user_table_add("", "p"));

  printf("user_table: all tests passed\n");
  return 0;
}
