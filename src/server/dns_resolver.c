#include "dns_resolver.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "socks5.h"

struct dns_job {
  struct socks5 *socks;
  fd_selector selector;
  int client_fd;
  char host[256];
  char service[6];
};

static void release_block_data(void *data) { socks5_release(data); }

static void *dns_worker(void *data) {
  struct dns_job *job = data;
  struct socks5 *socks = job->socks;
  struct addrinfo hints;
  struct addrinfo *result = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  const int error = getaddrinfo(job->host, job->service, &hints, &result);

  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = false;
  if (!socks->cancelled) {
    socks->dns_error = error;
    socks->dns_result = result;
    socks->dns_next = result;
    result = NULL;

    selector_status ss = selector_notify_block_done(
      job->selector, job->client_fd, socks, release_block_data
    );
    pthread_mutex_unlock(&socks->dns_mutex);
    if (ss != SELECTOR_SUCCESS) { socks5_release(socks); }
  } else {
    pthread_mutex_unlock(&socks->dns_mutex);
    socks5_release(socks);
  }

  if (result != NULL) freeaddrinfo(result);
  free(job);
  return NULL;
}

static void port_to_service(const struct socks5 *socks, char service[6]) {
  const unsigned port =
    ((unsigned) socks->request.port[0] << 8) | socks->request.port[1];
  snprintf(service, 6, "%u", port);
}

int dns_resolve_start(struct socks5 *socks, struct selector_key *key) {
  struct dns_job *job = malloc(sizeof(*job));
  if (job == NULL) return ENOMEM;

  job->socks = socks;
  job->selector = key->s;
  job->client_fd = socks->client_fd;
  memcpy(job->host, socks->request.address, socks->request.address_len);
  job->host[socks->request.address_len] = '\0';
  port_to_service(socks, job->service);

  pthread_mutex_lock(&socks->dns_mutex);
  socks->dns_pending = true;
  socks->dns_error = 0;
  socks->dns_result = NULL;
  socks->dns_next = NULL;
  pthread_mutex_unlock(&socks->dns_mutex);

  socks5_ref(socks);
  pthread_t thread;
  const int status = pthread_create(&thread, NULL, dns_worker, job);
  if (status != 0) {
    socks5_release(socks);
    free(job);
    pthread_mutex_lock(&socks->dns_mutex);
    socks->dns_pending = false;
    pthread_mutex_unlock(&socks->dns_mutex);
    return status;
  }
  pthread_detach(thread);
  return EINPROGRESS;
}
