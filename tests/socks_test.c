#include <check.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// Include implementation files so static SOCKS internals can be tested.
#include "../src/server/access_log.c"
#include "../src/server/auth.c"
#include "../src/server/connect.c"
#include "../src/server/dns_resolver.c"
#include "../src/server/hello.c"
#include "../src/server/metrics.c"
#include "../src/server/request.c"
#include "../src/server/socks5.c"
#include "../src/server/user_table.c"
#include "../src/shared/buffer.c"
#include "../src/shared/selector.c"
#include "../src/shared/stm.c"

static void buffer_push(buffer *b, const uint8_t *data, const size_t len) {
  size_t count;
  uint8_t *ptr = buffer_write_ptr(b, &count);
  ck_assert_uint_ge(count, len);
  memcpy(ptr, data, len);
  buffer_write_adv(b, (ssize_t) len);
}

static void assert_buffer_eq(buffer *b, const uint8_t *expected, size_t len) {
  size_t count;
  uint8_t *ptr = buffer_read_ptr(b, &count);
  ck_assert_uint_eq(count, len);
  ck_assert_mem_eq(ptr, expected, len);
}

static void drain_write_buffer(struct socks5 *socks) {
  size_t count;
  buffer_read_ptr(&socks->write_buffer, &count);
  buffer_read_adv(&socks->write_buffer, (ssize_t) count);
}

static void set_test_args(void) {
  static struct socks5args args;
  memset(&args, 0, sizeof(args));
  args.users[0].name = "alice";
  args.users[0].pass = "secret";
  socks5_set_args(&args);
  user_table_init();
  user_table_add("alice", "secret");
}

static void init_selector_for_test(void) {
  const struct selector_init conf = {
    .signal = SIGALRM,
    .select_timeout = {
      .tv_sec = 0,
      .tv_nsec = 1000000,
    },
  };
  ck_assert_int_eq(SELECTOR_SUCCESS, selector_init(&conf));
}

static void init_authed_socks(struct socks5 *socks, struct selector_key *key) {
  socks5_init(socks);
  key->data = socks;

  const uint8_t hello[] = {0x05, 0x01, SOCKS_HELLO_USERNAME_PASSWORD};
  buffer_push(&socks->read_buffer, hello, sizeof(hello));
  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(socks, key));
  drain_write_buffer(socks);
  ck_assert_int_eq(SOCKS5_ACTION_READ, socks5_handle_write(socks, key));

  const uint8_t auth[] = {
    AUTH_VERSION, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't',
  };
  buffer_push(&socks->read_buffer, auth, sizeof(auth));
  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(socks, key));
  drain_write_buffer(socks);
  ck_assert_int_eq(SOCKS5_ACTION_READ, socks5_handle_write(socks, key));
  ck_assert_uint_eq(SOCKS5_STATE_REQUEST_READ, stm_state(&socks->stm));
}

START_TEST(test_hello_selects_username_password_and_moves_to_auth) {
  struct socks5 socks;
  struct selector_key key = {0};
  socks5_init(&socks);
  key.data = &socks;

  const uint8_t hello[] = {
    SOCKS5_VERSION,
    2,
    SOCKS_HELLO_NOAUTHENTICATION_REQUIRED,
    SOCKS_HELLO_USERNAME_PASSWORD,
  };
  buffer_push(&socks.read_buffer, hello, sizeof(hello));

  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(&socks, &key));
  ck_assert_uint_eq(SOCKS5_STATE_HELLO_WRITE, stm_state(&socks.stm));
  ck_assert_uint_eq(SOCKS_HELLO_USERNAME_PASSWORD, socks.selected_method);

  const uint8_t expected[] = {SOCKS5_VERSION, SOCKS_HELLO_USERNAME_PASSWORD};
  assert_buffer_eq(&socks.write_buffer, expected, sizeof(expected));

  drain_write_buffer(&socks);
  ck_assert_int_eq(SOCKS5_ACTION_READ, socks5_handle_write(&socks, &key));
  ck_assert_uint_eq(SOCKS5_STATE_AUTH_READ, stm_state(&socks.stm));

  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_auth_success_and_failure_drive_state) {
  set_test_args();

  struct socks5 socks;
  struct selector_key key = {0};
  init_authed_socks(&socks, &key);
  ck_assert_uint_eq(AUTH_STATUS_SUCCESS, socks.auth_status);
  pthread_mutex_destroy(&socks.dns_mutex);

  socks5_init(&socks);
  key.data = &socks;

  const uint8_t hello[] = {SOCKS5_VERSION, 1, SOCKS_HELLO_USERNAME_PASSWORD};
  buffer_push(&socks.read_buffer, hello, sizeof(hello));
  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(&socks, &key));
  drain_write_buffer(&socks);
  ck_assert_int_eq(SOCKS5_ACTION_READ, socks5_handle_write(&socks, &key));

  const uint8_t bad_auth[] = {
    AUTH_VERSION, 5, 'a', 'l', 'i', 'c', 'e', 3, 'b', 'a', 'd',
  };
  buffer_push(&socks.read_buffer, bad_auth, sizeof(bad_auth));
  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(&socks, &key));
  ck_assert_uint_eq(AUTH_STATUS_FAILURE, socks.auth_status);

  const uint8_t expected[] = {AUTH_VERSION, AUTH_STATUS_FAILURE};
  assert_buffer_eq(&socks.write_buffer, expected, sizeof(expected));

  drain_write_buffer(&socks);
  ck_assert_int_eq(SOCKS5_ACTION_CLOSE, socks5_handle_write(&socks, &key));
  ck_assert_uint_eq(SOCKS5_STATE_ERROR, stm_state(&socks.stm));

  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_unsupported_command_writes_socks_reply_then_closes) {
  set_test_args();

  struct socks5 socks;
  struct selector_key key = {0};
  init_authed_socks(&socks, &key);

  const uint8_t bind_request[] = {
    SOCKS5_VERSION, 0x02, 0x00, SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90,
  };
  buffer_push(&socks.read_buffer, bind_request, sizeof(bind_request));

  ck_assert_int_eq(SOCKS5_ACTION_WRITE, socks5_handle_read(&socks, &key));
  ck_assert_uint_eq(SOCKS5_REPLY_COMMAND_NOT_SUPPORTED, socks.request_reply);

  size_t count;
  uint8_t *reply = buffer_read_ptr(&socks.write_buffer, &count);
  ck_assert_uint_eq(10, count);
  ck_assert_uint_eq(SOCKS5_VERSION, reply[0]);
  ck_assert_uint_eq(SOCKS5_REPLY_COMMAND_NOT_SUPPORTED, reply[1]);
  ck_assert_uint_eq(SOCKS5_ATYP_IPV4, reply[3]);

  drain_write_buffer(&socks);
  ck_assert_int_eq(SOCKS5_ACTION_CLOSE, socks5_handle_write(&socks, &key));
  ck_assert_uint_eq(SOCKS5_STATE_DONE, stm_state(&socks.stm));

  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

static const struct fd_handler dummy_handler = {
  .handle_read = NULL,
  .handle_write = NULL,
  .handle_close = NULL,
};

START_TEST(test_relay_client_read_keeps_selector_interests_alive) {
  init_selector_for_test();

  int client_pair[2];
  int origin_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, origin_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);

  struct socks5 socks;
  socks5_init(&socks);
  socks.client_fd = client_pair[1];
  socks.origin_fd = origin_pair[1];
  socks.relay_started = true;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.client_fd, &dummy_handler, OP_READ, &socks
    )
  );
  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.origin_fd, &dummy_handler, OP_NOOP, &socks
    )
  );

  const uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
  ck_assert_int_eq(
    (ssize_t) sizeof(payload), write(client_pair[0], payload, sizeof(payload))
  );

  struct selector_key key = {
    .s = selector,
    .fd = socks.client_fd,
    .data = &socks,
  };
  ck_assert_int_eq(SOCKS5_ACTION_NONE, socks5_relay_client_read(&socks, &key));
  assert_buffer_eq(&socks.read_buffer, payload, sizeof(payload));

  ck_assert(selector->fds[socks.client_fd].interest & OP_READ);
  ck_assert(selector->fds[socks.origin_fd].interest & OP_WRITE);

  selector_destroy(selector);
  close(client_pair[0]);
  close(client_pair[1]);
  close(origin_pair[0]);
  close(origin_pair[1]);
  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_domain_resolved_connect_falls_back_to_next_address) {
  init_selector_for_test();

  int client_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);

  struct socks5 socks;
  socks5_init(&socks);
  socks.client_fd = client_pair[1];
  socks.request.atyp = SOCKS5_ATYP_DOMAINNAME;

  struct sockaddr bad_addr;
  struct sockaddr next_bad_addr;
  memset(&bad_addr, 0, sizeof(bad_addr));
  memset(&next_bad_addr, 0, sizeof(next_bad_addr));
  bad_addr.sa_family = AF_UNSPEC;
  next_bad_addr.sa_family = AF_UNSPEC;

  struct addrinfo bad;
  struct addrinfo next_bad;
  memset(&bad, 0, sizeof(bad));
  memset(&next_bad, 0, sizeof(next_bad));

  bad.ai_socktype = SOCK_STREAM;
  bad.ai_addr = &bad_addr;
  bad.ai_addrlen = sizeof(bad_addr);
  bad.ai_next = &next_bad;

  next_bad.ai_socktype = SOCK_STREAM;
  next_bad.ai_addr = &next_bad_addr;
  next_bad.ai_addrlen = sizeof(next_bad_addr);

  socks.dns_error = 0;
  socks.dns_result = &bad;
  socks.dns_next = &bad;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.client_fd, &dummy_handler, OP_NOOP, &socks
    )
  );

  struct selector_key key = {
    .s = selector,
    .fd = socks.client_fd,
    .data = &socks,
  };
  const int status = start_resolved_connect(&socks, &key);

  ck_assert_int_ne(0, status);
  ck_assert_int_eq(-1, socks.origin_fd);
  ck_assert(!socks.origin_registered);
  ck_assert_ptr_null(socks.dns_next);

  selector_unregister_fd(selector, socks.client_fd);
  selector_destroy(selector);
  close(client_pair[0]);
  close(client_pair[1]);
  socks.dns_result = NULL;
  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_relay_origin_read_then_client_write) {
  init_selector_for_test();

  int client_pair[2];
  int origin_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, origin_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);

  struct socks5 socks;
  socks5_init(&socks);
  socks.client_fd = client_pair[1];
  socks.origin_fd = origin_pair[1];
  socks.relay_started = true;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.client_fd, &dummy_handler, OP_NOOP, &socks
    )
  );
  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.origin_fd, &dummy_handler, OP_READ, &socks
    )
  );

  const uint8_t payload[] = {'r', 'e', 's', 'p', 'o', 'n', 's', 'e'};
  ck_assert_int_eq(
    (ssize_t) sizeof(payload), write(origin_pair[0], payload, sizeof(payload))
  );

  struct selector_key origin_key = {
    .s = selector,
    .fd = socks.origin_fd,
    .data = &socks,
  };
  origin_read(&origin_key);

  assert_buffer_eq(&socks.write_buffer, payload, sizeof(payload));
  ck_assert(selector->fds[socks.client_fd].interest & OP_WRITE);
  ck_assert(selector->fds[socks.origin_fd].interest & OP_READ);

  struct selector_key client_key = {
    .s = selector,
    .fd = socks.client_fd,
    .data = &socks,
  };
  ck_assert_int_eq(
    SOCKS5_ACTION_NONE, socks5_relay_client_write(&socks, &client_key)
  );
  ck_assert(!buffer_can_read(&socks.write_buffer));

  uint8_t got[sizeof(payload)];
  ck_assert_int_eq(
    (ssize_t) sizeof(got), read(client_pair[0], got, sizeof(got))
  );
  ck_assert_mem_eq(got, payload, sizeof(payload));

  selector_destroy(selector);
  close(client_pair[0]);
  close(client_pair[1]);
  close(origin_pair[0]);
  close(origin_pair[1]);
  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_relay_half_close_waits_until_pending_client_bytes_are_flushed) {
  init_selector_for_test();

  int client_pair[2];
  int origin_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, origin_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);

  struct socks5 socks;
  socks5_init(&socks);
  socks.client_fd = client_pair[1];
  socks.origin_fd = origin_pair[1];
  socks.relay_started = true;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.client_fd, &dummy_handler, OP_READ, &socks
    )
  );
  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.origin_fd, &dummy_handler, OP_NOOP, &socks
    )
  );

  const uint8_t payload[] = {'p', 'e', 'n', 'd', 'i', 'n', 'g'};
  ck_assert_int_eq(
    (ssize_t) sizeof(payload), write(client_pair[0], payload, sizeof(payload))
  );

  struct selector_key client_key = {
    .s = selector,
    .fd = socks.client_fd,
    .data = &socks,
  };
  ck_assert_int_eq(
    SOCKS5_ACTION_NONE, socks5_relay_client_read(&socks, &client_key)
  );

  ck_assert_int_eq(0, close(client_pair[0]));
  client_pair[0] = -1;
  ck_assert_int_eq(
    SOCKS5_ACTION_NONE, socks5_relay_client_read(&socks, &client_key)
  );

  ck_assert(socks.client_eof);
  ck_assert(!socks.origin_write_shutdown);
  ck_assert(buffer_can_read(&socks.read_buffer));

  struct selector_key origin_key = {
    .s = selector,
    .fd = socks.origin_fd,
    .data = &socks,
  };
  origin_write(&origin_key);

  ck_assert(!buffer_can_read(&socks.read_buffer));
  ck_assert(socks.origin_write_shutdown);

  uint8_t got[sizeof(payload)];
  ck_assert_int_eq(
    (ssize_t) sizeof(got), read(origin_pair[0], got, sizeof(got))
  );
  ck_assert_mem_eq(got, payload, sizeof(payload));

  selector_destroy(selector);
  if (client_pair[0] >= 0) { close(client_pair[0]); }
  close(client_pair[1]);
  close(origin_pair[0]);
  close(origin_pair[1]);
  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

START_TEST(test_connection_close_unregisters_and_closes_fds) {
  init_selector_for_test();

  int client_pair[2];
  int origin_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, origin_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);

  struct socks5 *socks = calloc(1, sizeof(*socks));
  ck_assert_ptr_nonnull(socks);
  socks5_init(socks);
  socks5_ref(socks);

  socks->client_fd = client_pair[1];
  socks->origin_fd = origin_pair[1];
  socks->client_registered = true;
  socks->origin_registered = true;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks->client_fd, &dummy_handler, OP_READ, socks
    )
  );
  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks->origin_fd, &dummy_handler, OP_READ, socks
    )
  );

  socks5_connection_close(socks, selector);

  ck_assert(socks->closing);
  ck_assert_int_eq(-1, socks->client_fd);
  ck_assert_int_eq(-1, socks->origin_fd);
  ck_assert(!socks->client_registered);
  ck_assert(!socks->origin_registered);
  ck_assert_int_eq(FD_UNUSED, selector->fds[client_pair[1]].fd);
  ck_assert_int_eq(FD_UNUSED, selector->fds[origin_pair[1]].fd);

  close(client_pair[0]);
  close(origin_pair[0]);
  selector_destroy(selector);
  socks5_release(socks);
}
END_TEST

START_TEST(test_domain_dns_worker_stores_resolution_result) {
  init_selector_for_test();

  int client_pair[2];
  ck_assert_int_eq(0, socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair));

  fd_selector selector = selector_new(32);
  ck_assert_ptr_nonnull(selector);
  selector->selector_thread = pthread_self();

  struct socks5 socks;
  socks5_init(&socks);
  socks.client_fd = client_pair[1];
  socks.request.atyp = SOCKS5_ATYP_DOMAINNAME;
  memcpy(socks.request.address, "localhost", 9);
  socks.request.address_len = 9;
  socks.request.port[0] = 0x00;
  socks.request.port[1] = 0x50;

  ck_assert_int_eq(
    SELECTOR_SUCCESS,
    selector_register(
      selector, socks.client_fd, &dummy_handler, OP_NOOP, &socks
    )
  );

  struct selector_key key = {
    .s = selector,
    .fd = socks.client_fd,
    .data = &socks,
  };
  ck_assert_int_eq(EINPROGRESS, dns_resolve_start(&socks, &key));

  bool done = false;
  for (int i = 0; i < 200 && !done; i++) {
    pthread_mutex_lock(&socks.dns_mutex);
    done = !socks.dns_pending;
    pthread_mutex_unlock(&socks.dns_mutex);
    if (!done) {
      struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 10000000,
      };
      nanosleep(&ts, NULL);
    }
  }

  ck_assert(done);
  ck_assert_int_eq(0, socks.dns_error);
  ck_assert_ptr_nonnull(socks.dns_result);
  ck_assert_ptr_nonnull(socks.dns_next);

  selector_destroy(selector);
  close(client_pair[0]);
  close(client_pair[1]);
  if (socks.dns_result != NULL) { freeaddrinfo(socks.dns_result); }
  pthread_mutex_destroy(&socks.dns_mutex);
}
END_TEST

Suite *suite(void) {
  Suite *s = suite_create("socks5");
  TCase *tc = tcase_create("socks5");

  tcase_add_test(tc, test_hello_selects_username_password_and_moves_to_auth);
  tcase_add_test(tc, test_auth_success_and_failure_drive_state);
  tcase_add_test(tc, test_unsupported_command_writes_socks_reply_then_closes);
  tcase_add_test(tc, test_relay_client_read_keeps_selector_interests_alive);
  tcase_add_test(tc, test_domain_resolved_connect_falls_back_to_next_address);
  tcase_add_test(tc, test_relay_origin_read_then_client_write);
  tcase_add_test(
    tc, test_relay_half_close_waits_until_pending_client_bytes_are_flushed
  );
  tcase_add_test(tc, test_connection_close_unregisters_and_closes_fds);
  tcase_add_test(tc, test_domain_dns_worker_stores_resolution_result);
  suite_add_tcase(s, tc);

  return s;
}

int main(void) {
  SRunner *sr = srunner_create(suite());
  int number_failed;

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
