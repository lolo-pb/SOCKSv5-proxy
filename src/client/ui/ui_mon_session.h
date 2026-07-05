#ifndef UI_MON_SESSION_H
#define UI_MON_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "metrics_view.h"
#include "mon_protocol.h"

#define MAX_CREDENTIAL_LEN 255
#define STATUS_LEN 128
#define UI_RESPONSE_BUF_LEN (MON_RESPONSE_HEADER_LEN + (1 << 16))

struct ui_response {
  uint8_t status;
  uint16_t payload_len;
  const uint8_t *payload;
  uint8_t raw[UI_RESPONSE_BUF_LEN];
};

struct ui_state {
  const char *mon_addr;
  unsigned short mon_port;
  int mon_fd;
  char username[MAX_CREDENTIAL_LEN + 1];
  char password[MAX_CREDENTIAL_LEN + 1];
  char status[STATUS_LEN];
  bool authenticated;
};

typedef int (*payload_formatter)(const uint8_t *payload, size_t len, FILE *out);

const char *ui_mon_status_message(uint8_t status);
bool ui_authenticate(struct ui_state *state);
bool ui_run_command(
  const struct ui_state *state, uint8_t cmd, unsigned nargs, const char *arg0,
  const char *arg1, struct ui_response *out, char *message, size_t message_len
);
char *ui_format_payload(
  const struct ui_response *resp, payload_formatter formatter
);
char *ui_copy_text(const char *text);
bool ui_fetch_metrics_data(int fd, struct metrics_view_data *metrics);
char *ui_fetch_access_log_text(int fd);

#endif
