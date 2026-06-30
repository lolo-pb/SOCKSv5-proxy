#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "access_log.c"

int main(void) {
  access_log_init();
  assert(access_log_count() == 0);

  access_log_add("alice", "google.com", 443);
  access_log_add("bob", "192.168.1.1", 80);
  assert(access_log_count() == 2);

  unsigned count;
  const struct access_entry *entries = access_log_get(&count);
  assert(count == 2);
  assert(strcmp(entries[0].username, "alice") == 0);
  assert(strcmp(entries[0].dest_addr, "google.com") == 0);
  assert(entries[0].dest_port == 443);
  assert(strcmp(entries[1].username, "bob") == 0);
  assert(entries[1].dest_port == 80);

  /* circular: fill past MAX and verify count caps */
  access_log_init();
  for (unsigned i = 0; i < MAX_LOG_ENTRIES + 10; i++) {
    access_log_add("user", "host", 22);
  }
  assert(access_log_count() == MAX_LOG_ENTRIES);

  printf("access_log: all tests passed\n");
  return 0;
}
