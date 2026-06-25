#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <stdint.h>
#include <time.h>

#define MAX_LOG_ENTRIES 1024

struct access_entry {
  char username[256];
  char dest_addr[256];
  uint16_t dest_port;
  time_t timestamp;
};

void access_log_init(void);
void access_log_add(
  const char *username, const char *dest_addr, uint16_t dest_port
);
unsigned access_log_count(void);

/* returns pointer to internal array, count written to *out_count */
const struct access_entry *access_log_get(unsigned *out_count);

#endif
