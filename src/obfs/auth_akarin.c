#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include "encrypt.h"
#include "auth.h"
#include "obfsutil.h"
#include "crc32.h"
#include "base64.h"
#include "obfs.h"

static const int auth_akarin_rand_init_loop = 0;

typedef struct auth_akarin_global_data {
    uint8_t local_client_id[4];
    uint32_t connection_id;
} auth_akarin_global_data;

// akarin_rand akarin_spec_a
typedef struct auth_akarin_spec_a_data {
    int *data_size_list;
    int data_size_list_length;
    int *data_size_list2;
    int data_size_list2_length;
} auth_akarin_spec_a_data;

typedef struct auth_akarin_local_data {
    int has_sent_header;
    char *recv_buffer;
    int recv_buffer_size;
    uint32_t recv_id;
    uint32_t pack_id;
    char *salt;
    uint8_t *user_key;
    char uid[4];
    int user_key_len;
    int last_data_len;
    uint8_t last_client_hash[16];
    uint8_t last_server_hash[16];
    shift128plus_ctx random_client;
    shift128plus_ctx random_server;
    int cipher_init_flag;
    cipher_env_t cipher;
    enc_ctx_t *cipher_client_ctx;
    enc_ctx_t *cipher_server_ctx;
    int send_tcp_mss;
    int recv_tcp_mss;
    int send_back_cmd;

    unsigned int (*get_tcp_send_rand_len)(
            struct auth_akarin_local_data *local,
            server_info *server,
            int datalength,
            shift128plus_ctx *random,
            uint8_t *last_hash
    );

    unsigned int(*get_tcp_recv_rand_len)(
    struct auth_akarin_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
        );

    void *auth_akarin_special_data;
} auth_akarin_local_data;

void auth_akarin_local_data_init(auth_akarin_local_data *local) {
    local->has_sent_header = 0;
    local->recv_buffer = (char *) malloc(16384);
    local->recv_buffer_size = 0;
    local->recv_id = 1;
    local->pack_id = 1;
    local->salt = "";
    local->user_key = 0;
    local->user_key_len = 0;
    local->cipher_init_flag = 0;
    local->cipher_client_ctx = 0;
    local->cipher_server_ctx = 0;
    local->get_tcp_send_rand_len = NULL;
    local->get_tcp_recv_rand_len = NULL;
    local->send_tcp_mss = 2000;
    local->recv_tcp_mss = 2000;
    local->send_back_cmd = 0;
}

unsigned int auth_akarin_rand_get_send_rand_len(
        auth_akarin_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    if (datalength + server->overhead > local->send_tcp_mss) {
        shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength, auth_akarin_rand_init_loop);
        return (int)(shift128plus_next(random) % 521);
    }
    if (datalength >= 1440 || datalength + server->overhead == local->send_tcp_mss)
        return 0;
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength, auth_akarin_rand_init_loop);
    if (datalength > 1300)
        return (unsigned int) (shift128plus_next(random) % 31);
    if (datalength > 900)
        return (unsigned int) (shift128plus_next(random) % 127);
    if (datalength > 400)
        return (unsigned int) (shift128plus_next(random) % 521);
    return (unsigned int) (shift128plus_next(random) % (unsigned int)(local->send_tcp_mss - datalength - server->overhead));
}

unsigned int auth_akarin_rand_get_recv_rand_len(
    auth_akarin_local_data *local,
    server_info *server,
    int datalength,
    shift128plus_ctx *random,
    uint8_t *last_hash
    ) {
    if (datalength + server->overhead > local->recv_tcp_mss) {
        shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength, auth_akarin_rand_init_loop);
        return (int)(shift128plus_next(random) % 521);
    }
    if (datalength >= 1440 || datalength + server->overhead == local->recv_tcp_mss)
        return 0;
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength, auth_akarin_rand_init_loop);
    if (datalength > 1300)
        return (unsigned int)(shift128plus_next(random) % 31);
    if (datalength > 900)
        return (unsigned int)(shift128plus_next(random) % 127);
    if (datalength > 400)
        return (unsigned int)(shift128plus_next(random) % 521);
    return (unsigned int)(shift128plus_next(random) % (unsigned int)(local->recv_tcp_mss - datalength - server->overhead));
}

unsigned int auth_akarin_spec_a_get_rand_len(
        auth_akarin_local_data *local,
        server_info *server,
        int datalength,
        shift128plus_ctx *random,
        uint8_t *last_hash
) {
    if (datalength > 1440)
        return 0;
    uint16_t overhead = server->overhead;
    auth_akarin_spec_a_data *special_data = (auth_akarin_spec_a_data *) local->auth_akarin_special_data;

    int other_data_size = datalength + overhead;

    // auth_akarin_spec_a_get_rand_len
    shift128plus_init_from_bin_datalen(random, last_hash, 16, datalength, auth_akarin_rand_init_loop);
    int pos = find_pos(special_data->data_size_list, special_data->data_size_list_length, other_data_size);
    uint64_t final_pos = pos + shift128plus_next(random) % special_data->data_size_list_length;
    if (final_pos < special_data->data_size_list_length) {
        return special_data->data_size_list[final_pos] - other_data_size;
    }

    int pos2 = find_pos(special_data->data_size_list2, special_data->data_size_list2_length, other_data_size);
    uint64_t final_pos2 = pos2 + shift128plus_next(random) % special_data->data_size_list2_length;
    if (final_pos2 < special_data->data_size_list2_length) {
        return special_data->data_size_list2[final_pos2] - other_data_size;
    }
    if (final_pos2 < pos2 + special_data->data_size_list2_length - 1) {
        return 0;
    }

    if (datalength > 1300)
        return (unsigned int) (shift128plus_next(random) % 31);
    if (datalength > 900)
        return (unsigned int) (shift128plus_next(random) % 127);
    if (datalength > 400)
        return (unsigned int) (shift128plus_next(random) % 521);
    return (unsigned int) (shift128plus_next(random) % 1021);
}

void auth_akarin_spec_a_init_data_size(obfs *self, server_info *server) {
    auth_akarin_spec_a_data *special_data = (auth_akarin_spec_a_data *)
            ((auth_akarin_local_data *) self->l_data)->auth_akarin_special_data;

    shift128plus_ctx *random = (shift128plus_ctx *) malloc(sizeof(shift128plus_ctx));

    shift128plus_init_from_bin(random, server->key, 16);
    special_data->data_size_list_length = shift128plus_next(random) % 8 + 4;
    special_data->data_size_list = (int *) malloc(special_data->data_size_list_length * sizeof(int));
    for (int i = 0; i < special_data->data_size_list_length; i++) {
        special_data->data_size_list[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list,
          special_data->data_size_list_length,
          sizeof(int),
          data_size_list_compare
    );

    special_data->data_size_list2_length = shift128plus_next(random) % 16 + 8;
    special_data->data_size_list2 = (int *) malloc(special_data->data_size_list2_length * sizeof(int));
    for (int i = 0; i < special_data->data_size_list2_length; i++) {
        special_data->data_size_list2[i] = shift128plus_next(random) % 2340 % 2040 % 1440;
    }
    // stdlib qsort
    qsort(special_data->data_size_list2,
          special_data->data_size_list2_length,
          sizeof(int),
          data_size_list_compare
    );

    free(random);
}

void *auth_akarin_rand_init_data() {
    auth_akarin_global_data *global = (auth_akarin_global_data *) malloc(sizeof(auth_akarin_global_data));
    rand_bytes(global->local_client_id, 4);
    rand_bytes((uint8_t *) &global->connection_id, 4);
    global->connection_id &= 0xFFFFFF;
    return global;
}

void *auth_akarin_spec_a_init_data() {
    return auth_akarin_rand_init_data();
}

obfs *auth_akarin_rand_new_obfs() {
    obfs *self = new_obfs();
    self->l_data = malloc(sizeof(auth_akarin_local_data));
    auth_akarin_local_data_init((auth_akarin_local_data *) self->l_data);
    ((auth_akarin_local_data *) self->l_data)->salt = "auth_akarin_rand";
    ((auth_akarin_local_data *) self->l_data)->get_tcp_send_rand_len = auth_akarin_rand_get_send_rand_len;
    ((auth_akarin_local_data *) self->l_data)->get_tcp_recv_rand_len = auth_akarin_rand_get_recv_rand_len;
    return self;
}

obfs *auth_akarin_spec_a_new_obfs() {
    obfs *self = new_obfs();
    self->l_data = malloc(sizeof(auth_akarin_local_data));
    auth_akarin_local_data_init((auth_akarin_local_data *) self->l_data);
    ((auth_akarin_local_data *) self->l_data)->salt = "auth_akarin_spec_a";
    //((auth_akarin_local_data *) self->l_data)->get_tcp_send_rand_len = auth_akarin_spec_a_get_send_rand_len;
    //((auth_akarin_local_data *) self->l_data)->get_tcp_recv_rand_len = auth_akarin_spec_a_get_recv_rand_len;
    auth_akarin_spec_a_data *special_data = (auth_akarin_spec_a_data *) malloc(sizeof(auth_akarin_spec_a_data));
    special_data->data_size_list = NULL;
    special_data->data_size_list_length = 0;
    special_data->data_size_list2 = NULL;
    special_data->data_size_list2_length = 0;
    ((auth_akarin_local_data *) self->l_data)->auth_akarin_special_data = special_data;
    return self;
}

int auth_akarin_rand_get_overhead(obfs *self) {
    return 4;
}

int auth_akarin_spec_a_get_overhead(obfs *self) {
    return auth_akarin_rand_get_overhead(self);
}

void auth_akarin_rand_dispose(obfs *self) {
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    if (local->user_key != NULL) {
        free(local->user_key);
        local->user_key = NULL;
    }
    if (local->cipher_init_flag) {
        if (local->cipher_client_ctx) {
            enc_ctx_release(&local->cipher, local->cipher_client_ctx);
        }
        if (local->cipher_server_ctx) {
            enc_ctx_release(&local->cipher, local->cipher_server_ctx);
        }
        enc_release(&local->cipher);
        local->cipher_init_flag = 0;
    }
    free(local);
    self->l_data = NULL;
    dispose_obfs(self);
}

void auth_akarin_spec_a_dispose(obfs *self) {
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;
    auth_akarin_spec_a_data *special_data = (auth_akarin_spec_a_data *) local->auth_akarin_special_data;
    if (local->auth_akarin_special_data != NULL) {
        if (special_data->data_size_list != NULL) {
            free(special_data->data_size_list);
            special_data->data_size_list = NULL;
            special_data->data_size_list_length = 0;
        }
        if (special_data->data_size_list2 != NULL) {
            free(special_data->data_size_list2);
            special_data->data_size_list2 = NULL;
            special_data->data_size_list2_length = 0;
        }
        free(local->auth_akarin_special_data);
        local->auth_akarin_special_data = NULL;
    }
    auth_akarin_rand_dispose(self);
}

void auth_akarin_rand_set_server_info(obfs *self, server_info *server) {
    // dont change server.overhead in there
    // the server.overhead are counted from the local.c
    // the input's server.overhead is the total server.overhead that sum of all the plugin's overhead
    memmove(&self->server, server, sizeof(server_info));
}

void auth_akarin_spec_a_set_server_info(obfs *self, server_info *server) {
    memmove(&self->server, server, sizeof(server_info));
    // auth_akarin_spec_a_init_data_size() init in there
    auth_akarin_spec_a_init_data_size(self, &self->server);
}

unsigned int auth_akarin_udp_get_rand_len(shift128plus_ctx *random, uint8_t *last_hash) {
    shift128plus_init_from_bin(random, last_hash, 16);
    return shift128plus_next(random) % 127;
}

unsigned int auth_akarin_get_client_rand_len(auth_akarin_local_data *local, server_info *server, int datalength) {
    return local->get_tcp_send_rand_len(local, server, datalength, &local->random_client, local->last_client_hash);
}

unsigned int auth_akarin_get_server_rand_len(auth_akarin_local_data *local, server_info *server, int datalength) {
    return local->get_tcp_recv_rand_len(local, server, datalength, &local->random_server, local->last_server_hash);
}

int auth_akarin_rand_pack_data(char *data, int datalength, char *outdata, auth_akarin_local_data *local,
                           server_info *server) {
    unsigned int rand_len;
    int start_pos = 2;
    int out_size;

    if (local->send_back_cmd != 0)
    {
        int cmdlen = 2;
        local->send_tcp_mss = local->recv_tcp_mss;
        rand_len = auth_akarin_get_client_rand_len(local, server, datalength + cmdlen);
        out_size = (int) rand_len + datalength + cmdlen + 2;
        start_pos += cmdlen;
        outdata[0] = (char)(local->send_back_cmd ^ local->last_client_hash[14]);
        outdata[1] = (char)((local->send_back_cmd >> 8) ^ local->last_client_hash[15]);
        outdata[2] = (char)(datalength ^ local->last_client_hash[12]);
        outdata[3] = (char)((datalength >> 8) ^ local->last_client_hash[13]);
        local->send_back_cmd = 0;
    }
    else
    {

        rand_len = auth_akarin_get_client_rand_len(local, server, datalength);
        out_size = (int) rand_len + datalength + 2;
        outdata[0] = (char) ((uint8_t) datalength ^ local->last_client_hash[14]);
        outdata[1] = (char) ((uint8_t) (datalength >> 8) ^ local->last_client_hash[15]);
    }

    {
        uint8_t *rnd_data = (uint8_t *)malloc(rand_len);
        rand_bytes(rnd_data, (int) rand_len);
        if (datalength > 0) {
            size_t out_len;
            ss_encrypt_buffer(&local->cipher, local->cipher_client_ctx,
                              data, datalength, &outdata[start_pos], &out_len);
            memcpy(outdata + start_pos + datalength, rnd_data, rand_len);
        } else {
            memcpy(outdata + start_pos, rnd_data, rand_len);
        }
        free(rnd_data);
    }

    uint8_t key_len = (uint8_t) (local->user_key_len + 4);
    uint8_t *key = (uint8_t *)malloc(key_len);
    memcpy(key, local->user_key, local->user_key_len);
    memintcopy_lt(key + key_len - 4, local->pack_id);
    ++local->pack_id;

    ss_md5_hmac_with_key((char *) local->last_client_hash, outdata, out_size, key, key_len);
    memcpy(outdata + out_size, local->last_client_hash, 2);
    free(key);
    return out_size + 2;
}

int auth_akarin_rand_pack_auth_data(auth_akarin_global_data *global, server_info *server, auth_akarin_local_data *local,
                                char *data, int datalength, char *outdata) {
    const int authhead_len = 4 + 8 + 4 + 16 + 4;
    const char *salt = local->salt;
    int out_size = authhead_len;

    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t *) &global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }

    char encrypt[20];

    uint8_t *key = (uint8_t *)malloc(server->iv_len + server->key_len);
    uint8_t key_len = (uint8_t) (server->iv_len + server->key_len);
    memcpy(key, server->iv, server->iv_len);
    memcpy(key + server->iv_len, server->key, server->key_len);

    time_t t = time(NULL);
    memintcopy_lt(encrypt, (uint32_t) t);
    memcpy(encrypt + 4, global->local_client_id, 4);
    memintcopy_lt(encrypt + 8, global->connection_id);
    encrypt[12] = (char) server->overhead;
    encrypt[13] = (char) (server->overhead >> 8);
    local->send_tcp_mss = 1024;
    local->recv_tcp_mss = local->send_tcp_mss;
    encrypt[14] = (char)local->send_tcp_mss;
    encrypt[15] = (char)(local->send_tcp_mss >> 8);

    // first 12 bytes
    {
        rand_bytes((uint8_t *) outdata, 4);
        ss_md5_hmac_with_key((char *) local->last_client_hash, (char *) outdata, 4, key, key_len);
        memcpy(outdata + 4, local->last_client_hash, 8);
    }
    free(key);
    // uid & 16 bytes auth data
    {
        uint8_t uid[4];
        if (local->user_key == NULL) {
            if (server->param != NULL && server->param[0] != 0) {
                char *param = server->param;
                char *delim = strchr(param, ':');
                if (delim != NULL) {
                    char uid_str[16] = "";
                    strncpy(uid_str, param, delim - param);
                    char key_str[128];
                    strcpy(key_str, delim + 1);
                    long uid_long = strtol(uid_str, NULL, 10);
                    memintcopy_lt((char *) local->uid, (uint32_t) uid_long);

                    local->user_key_len = (int) strlen(key_str);
                    local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                    memcpy(local->user_key, key_str, local->user_key_len);
                }
            }
            if (local->user_key == NULL) {
                rand_bytes((uint8_t *) local->uid, 4);

                local->user_key_len = (int) server->key_len;
                local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                memcpy(local->user_key, server->key, local->user_key_len);
            }
        }
        for (int i = 0; i < 4; ++i) {
            uid[i] = local->uid[i] ^ local->last_client_hash[8 + i];
        }

        char encrypt_key_base64[256] = {0};
        unsigned char *encrypt_key = (unsigned char *)malloc(local->user_key_len);
        memcpy(encrypt_key, local->user_key, local->user_key_len);
        base64_encode(encrypt_key, (unsigned int) local->user_key_len, encrypt_key_base64);
        free(encrypt_key);

        int salt_len = (int)strlen(salt);
        int base64_len = (local->user_key_len + 2) / 3 * 4;
        memcpy(encrypt_key_base64 + base64_len, salt, salt_len);

        char enc_key[16];
        int enc_key_len = base64_len + salt_len;
        bytes_to_key_with_size(encrypt_key_base64, (size_t) enc_key_len, (uint8_t *) enc_key, 16);
        char encrypt_data[16];
        ss_aes_128_cbc(encrypt, encrypt_data, enc_key);
        memcpy(encrypt, uid, 4);
        memcpy(encrypt + 4, encrypt_data, 16);
    }
    // final HMAC
    {
        ss_md5_hmac_with_key((char *) local->last_server_hash, encrypt, 20, local->user_key, local->user_key_len);
        memcpy(outdata + 12, encrypt, 20);
        memcpy(outdata + 12 + 20, local->last_server_hash, 4);
    }

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(local->last_client_hash, 16, password + strlen(password));
    local->cipher_init_flag = 1;
    enc_init(&local->cipher, password, "chacha20");
    local->cipher_client_ctx = malloc(sizeof(enc_ctx_t));
    local->cipher_server_ctx = malloc(sizeof(enc_ctx_t));
    {
        char iv[8];
        memcpy(iv, local->last_client_hash, 8);
        enc_ctx_init(&local->cipher, local->cipher_client_ctx, 1, iv);
    }
    {
        enc_ctx_init(&local->cipher, local->cipher_server_ctx, 0, NULL);
        buffer_t *plain = buffer_alloc(64);
        memcpy(plain->array, local->last_server_hash, 8);
        plain->len = 8;
        ss_decrypt(&local->cipher, plain, local->cipher_server_ctx, 8);
        buffer_free(&plain);
    }

    out_size += auth_akarin_rand_pack_data(data, datalength, outdata + out_size, local, server);

    return out_size;
}

int auth_akarin_rand_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;
    char *out_buffer = (char *) malloc((size_t) (datalength * 2 + 4096));
    char *buffer = out_buffer;
    char *data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = 1200;
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_akarin_rand_pack_auth_data((auth_akarin_global_data *) self->server.g_data, &self->server, local,
                                               data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    int unit_size = server->tcp_mss - server->overhead;
    while (len > unit_size) {
        pack_len = auth_akarin_rand_pack_data(data, unit_size, buffer, local, &self->server);
        buffer += pack_len;
        data += unit_size;
        len -= unit_size;
    }
    if (len > 0) {
        pack_len = auth_akarin_rand_pack_data(data, len, buffer, local, &self->server);
        buffer += pack_len;
    }
    len = (int) (buffer - out_buffer);
    if ((int) *capacity < len) {
        *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (len * 2));
        // TODO check realloc failed
        plaindata = *pplaindata;
    }
    local->last_data_len = datalength;
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_akarin_rand_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;
    server_info *server = (server_info *) &self->server;
    uint8_t *recv_buffer = (uint8_t *) local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    int key_len = local->user_key_len + 4;
    uint8_t *key = (uint8_t *) malloc((size_t) key_len);
    memcpy(key, local->user_key, local->user_key_len);

    char *out_buffer = (char *) malloc((size_t) local->recv_buffer_size);
    char *buffer = out_buffer;
    char error = 0;
    while (local->recv_buffer_size > 4) {
        memintcopy_lt(key + key_len - 4, local->recv_id);

        int data_len = (int) (((unsigned) (recv_buffer[1] ^ local->last_server_hash[15]) << 8) +
                              (recv_buffer[0] ^ local->last_server_hash[14]));
        int rand_len = auth_akarin_get_server_rand_len(local, server, data_len);
        int len = rand_len + data_len;
        if (len >= 4096) {
            local->recv_buffer_size = 0;
            error = 1;
            break;
        }
        if ((len += 4) > local->recv_buffer_size)
            break;

        char hash[16];
        ss_md5_hmac_with_key(hash, (char *) recv_buffer, len - 2, key, key_len);
        if (memcmp(hash, recv_buffer + len - 2, 2)) {
            local->recv_buffer_size = 0;
            error = 1;
            break;
        }

        int pos = 2;
        size_t out_len;
        ss_decrypt_buffer(&local->cipher, local->cipher_server_ctx,
                          (char *) recv_buffer + pos, data_len, buffer, &out_len);

        if (local->recv_id == 1) {
            server->tcp_mss = local->recv_tcp_mss = (uint8_t) buffer[0] | ((uint8_t) buffer[1] << 8);
            memmove(buffer, buffer + 2, out_len -= 2);
            local->send_back_cmd = 0xff00;
        }
        memcpy(local->last_server_hash, hash, 16);
        ++local->recv_id;
        buffer += out_len;
        memmove(recv_buffer, recv_buffer + len, local->recv_buffer_size -= len);
    }
    int len;
    if (error == 0) {
        len = (int) (buffer - out_buffer);
        if ((int) *capacity < len) {
            *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (len * 2));
            plaindata = *pplaindata;
        }
        memmove(plaindata, out_buffer, len);
    } else {
        len = -1;
    }
    free(out_buffer);
    free(key);
    return len;
}

int auth_akarin_rand_client_udp_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;
    char *out_buffer = (char *)malloc(datalength + 1024);

    if (local->user_key == NULL) {
        if (self->server.param != NULL && self->server.param[0] != 0) {
            char *param = self->server.param;
            char *delim = strchr(param, ':');
            if (delim != NULL) {
                char uid_str[16] = "";
                strncpy(uid_str, param, delim - param);
                char key_str[128];
                strcpy(key_str, delim + 1);
                long uid_long = strtol(uid_str, NULL, 10);
                memintcopy_lt(local->uid, (uint32_t) uid_long);

                local->user_key_len = (int) strlen(key_str);
                local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
                memcpy(local->user_key, key_str, local->user_key_len);
            }
        }
        if (local->user_key == NULL) {
            rand_bytes((uint8_t *) local->uid, 4);

            local->user_key_len = (int) self->server.key_len;
            local->user_key = (uint8_t *) malloc((size_t) local->user_key_len);
            memcpy(local->user_key, self->server.key, local->user_key_len);
        }
    }

    char auth_data[3];
    uint8_t hash[16];
    ss_md5_hmac_with_key((char *) hash, auth_data, 3, server->key, server->key_len);
    int rand_len = auth_akarin_udp_get_rand_len(&local->random_client, hash);
    uint8_t *rnd_data = (uint8_t *)malloc(rand_len);
    rand_bytes(rnd_data, (int) rand_len);
    int outlength = datalength + rand_len + 8;

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(hash, 16, password + strlen(password));

    {
        enc_init(&local->cipher, password, "chacha20");
        enc_ctx_t ctx;
        char iv[8];
        memcpy(iv, server->key, 8);
        enc_ctx_init(&local->cipher, &ctx, 1, iv);
        size_t out_len;
        ss_encrypt_buffer(&local->cipher, &ctx,
                          plaindata, datalength, out_buffer, &out_len);
        enc_ctx_release(&local->cipher, &ctx);
        enc_release(&local->cipher);
    }
    uint8_t uid[4];
    for (int i = 0; i < 4; ++i) {
        uid[i] = local->uid[i] ^ hash[i];
    }
    memmove(out_buffer + datalength, rnd_data, rand_len);
    memmove(out_buffer + outlength - 8, auth_data, 3);
    memmove(out_buffer + outlength - 5, uid, 4);
    free(rnd_data);

    ss_md5_hmac_with_key((char *) hash, out_buffer, outlength - 1, local->user_key, local->user_key_len);
    memmove(out_buffer + outlength - 1, hash, 1);

    if ((int) *capacity < outlength) {
        *pplaindata = (char *) realloc(*pplaindata, *capacity = (size_t) (outlength * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, outlength);
    free(out_buffer);
    return outlength;
}

int auth_akarin_rand_client_udp_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity) {
    if (datalength <= 8)
        return 0;

    char *plaindata = *pplaindata;
    server_info *server = (server_info *) &self->server;
    auth_akarin_local_data *local = (auth_akarin_local_data *) self->l_data;

    uint8_t hash[16];
    ss_md5_hmac_with_key((char *) hash, plaindata, datalength - 1, local->user_key, local->user_key_len);

    if (*hash != ((uint8_t *) plaindata)[datalength - 1])
        return 0;

    ss_md5_hmac_with_key((char *) hash, plaindata + datalength - 8, 7, server->key, server->key_len);

    int rand_len = auth_akarin_udp_get_rand_len(&local->random_server, hash);
    int outlength = datalength - rand_len - 8;

    char password[256] = {0};
    base64_encode(local->user_key, local->user_key_len, password);
    base64_encode(hash, 16, password + strlen(password));

    {
        enc_init(&local->cipher, password, "chacha20");
        enc_ctx_t ctx;
        enc_ctx_init(&local->cipher, &ctx, 0, NULL);
        size_t out_len;
        char iv[8];
        memcpy(iv, server->key, 8);
        ss_decrypt_buffer(&local->cipher, &ctx, iv, 8, plaindata, &out_len);
        ss_decrypt_buffer(&local->cipher, &ctx, plaindata, outlength, plaindata, &out_len);
        enc_ctx_release(&local->cipher, &ctx);
        enc_release(&local->cipher);
    }

    return outlength;
}
