#include "access_log.h"

#include <string.h>

static struct {
  struct access_entry entries[MAX_LOG_ENTRIES];
  unsigned count;
  unsigned next; /* write index (circular) */
} log_state;

void access_log_init(void) { memset(&log_state, 0, sizeof(log_state)); }

void access_log_add(
  const char *username, const char *dest_addr, uint16_t dest_port
) {
  struct access_entry *e = &log_state.entries[log_state.next];

  const char *user = (username != NULL) ? username : "-";
  const char *addr = (dest_addr != NULL) ? dest_addr : "-";
  strncpy(e->username, user, sizeof(e->username) - 1);
  e->username[sizeof(e->username) - 1] = '\0';
  strncpy(e->dest_addr, addr, sizeof(e->dest_addr) - 1);
  e->dest_addr[sizeof(e->dest_addr) - 1] = '\0';
  e->dest_port = dest_port;
  e->timestamp = time(NULL);

  log_state.next = (log_state.next + 1) % MAX_LOG_ENTRIES;
  if (log_state.count < MAX_LOG_ENTRIES) log_state.count++;
}

unsigned access_log_count(void) { return log_state.count; }

const struct access_entry *access_log_get(unsigned *out_count) {
  if (out_count != NULL) *out_count = log_state.count;
  /* when not full, entries start at 0; when full, oldest is at next */
  return log_state.entries;
}

unsigned access_log_oldest_index(void) {
  return (log_state.count < MAX_LOG_ENTRIES) ? 0 : log_state.next;
}
