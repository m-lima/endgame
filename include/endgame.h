#pragma once

#include <stdint.h>
#include <ngx_string.h>

typedef struct EndgameKey {
  uint8_t bytes[32];
} EndgameKey;

typedef struct EndgameOidc {
  size_t id;
  uint32_t signature;
} EndgameOidc;

typedef struct EndgameError {
  uint16_t status;
  ngx_str_t msg;
} EndgameError;

typedef struct EndgameResult {
  const void *request;
  uint16_t status;
  ngx_str_t cookie;
  ngx_str_t redirect;
} EndgameResult;

void endgame_ngx_str_t_trim(ngx_str_t *string);

void endgame_conf_clear(void);

struct EndgameKey endgame_conf_random_key(void);

char *endgame_conf_load_key(ngx_str_t path, struct EndgameKey *key);

char *endgame_conf_push(struct EndgameKey key,
                        ngx_str_t discovery_url,
                        ngx_str_t session_name,
                        uint64_t session_ttl,
                        ngx_str_t session_domain,
                        ngx_str_t client_id,
                        ngx_str_t client_secret,
                        ngx_str_t client_callback_url,
                        struct EndgameOidc *oidc_ref);

struct EndgameError endgame_auth_redirect_login_url(struct EndgameKey master_key,
                                                    struct EndgameOidc oidc_ref,
                                                    ngx_str_t redirect_host,
                                                    ngx_str_t redirect_path,
                                                    ngx_str_t *login_url,
                                                    void *pool);

struct EndgameError endgame_auth_exchange_token(struct EndgameKey master_key,
                                                ngx_str_t query,
                                                const void *request,
                                                int pipe,
                                                void *pool);

struct EndgameError endgame_token_decrypt(struct EndgameKey key,
                                          ngx_str_t src,
                                          ngx_str_t *email,
                                          ngx_str_t *given_name,
                                          ngx_str_t *family_name,
                                          void *pool);
