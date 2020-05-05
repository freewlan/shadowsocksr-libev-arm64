#include <stdint.h>
#include <time.h>

#include "obfsutil.h"
#include "encrypt.h"

static const uint32_t g_endian_test = 1;

int get_head_size(char *plaindata, int size, int def_size) {
    if (plaindata == NULL || size < 2)
        return def_size;
    int head_type = plaindata[0] & 0x7;
    if (head_type == 1)
        return 7;
    if (head_type == 4)
        return 19;
    if (head_type == 3)
        return 4 + plaindata[1];
    return def_size;
}

static int shift128plus_init_flag = 0;
static uint64_t shift128plus_s[2] = {0x10000000, 0xFFFFFFFF};

void init_shift128plus(void) {
    if (shift128plus_init_flag == 0) {
        shift128plus_init_flag = 1;
        uint32_t seed = (uint32_t)time(NULL);
        shift128plus_s[0] = seed | 0x100000000L;
        shift128plus_s[1] = ((uint64_t)seed << 32) | 0x1;
    }
}

uint64_t xorshift128plus(void) {
    uint64_t x = shift128plus_s[0];
    uint64_t const y = shift128plus_s[1];
    shift128plus_s[0] = y;
    x ^= x << 23; // a
    x ^= x >> 17; // b
    x ^= y ^ (y >> 26); // c
    shift128plus_s[1] = x;
    return x + y;
}

int ss_md5_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len)
{
    uint8_t auth_key[MAX_IV_LENGTH + MAX_KEY_LENGTH];
    memcpy(auth_key, iv, enc_iv_len);
    memcpy(auth_key + enc_iv_len, enc_key, enc_key_len);
    return ss_md5_hmac_with_key(auth, msg, msg_len, auth_key, enc_iv_len + enc_key_len);
}

int ss_sha1_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len)
{
    uint8_t auth_key[MAX_IV_LENGTH + MAX_KEY_LENGTH];
    memcpy(auth_key, iv, enc_iv_len);
    memcpy(auth_key + enc_iv_len, enc_key, enc_key_len);
    return ss_sha1_hmac_with_key(auth, msg, msg_len, auth_key, enc_iv_len + enc_key_len);
}

void memintcopy_lt(void *mem, uint32_t val) {
    ((uint8_t *)mem)[0] = (uint8_t)(val);
    ((uint8_t *)mem)[1] = (uint8_t)(val >> 8);
    ((uint8_t *)mem)[2] = (uint8_t)(val >> 16);
    ((uint8_t *)mem)[3] = (uint8_t)(val >> 24);
}

int data_size_list_compare(const void *a, const void *b) {
    return (*(int *)a - *(int *)b);
}

int find_pos(int arr[], int length, int key) {
    int low = 0;
    int high = length - 1;
    int middle = -1;

    if (key > arr[high])
        return length;

    while (low < high) {
        middle = (low + high) / 2;
        if (key > arr[middle]) {
            low = middle + 1;
        }
        else if (key <= arr[middle]) {
            high = middle;
        }
    }
    return low;
}

void i64_memcpy(uint8_t *target, uint8_t *source) {
    for (int i = 0; i < 8; ++i)
        target[i] = source[7 - i];
}

uint64_t shift128plus_next(shift128plus_ctx *ctx) {
    uint64_t x = ctx->v[0];
    uint64_t y = ctx->v[1];
    ctx->v[0] = y;
    x ^= x << 23;
    x ^= (y ^ (x >> 17) ^ (y >> 26));
    ctx->v[1] = x;
    return x + y;
}

void shift128plus_init_from_bin(shift128plus_ctx *ctx, uint8_t *bin, int bin_size) {
    uint8_t fill_bin[16] = { 0 };
    memcpy(fill_bin, bin, bin_size);
    if (*(uint8_t *)&g_endian_test == 1) {
        memcpy(ctx, fill_bin, 16);
    }
    else {
        i64_memcpy((uint8_t *)ctx, fill_bin);
        i64_memcpy((uint8_t *)ctx + 8, fill_bin + 8);
    }
}

void shift128plus_init_from_bin_datalen(shift128plus_ctx *ctx, uint8_t *bin, int bin_size, int datalen, int init_loop) {
    uint8_t fill_bin[16] = { 0 };
    memcpy(fill_bin, bin, bin_size);
    fill_bin[0] = datalen;
    fill_bin[1] = datalen >> 8;
    if (*(uint8_t *)&g_endian_test == 1) {
        memcpy(ctx, fill_bin, 16);
    }
    else {
        i64_memcpy((uint8_t *)ctx, fill_bin);
        i64_memcpy((uint8_t *)ctx + 8, fill_bin + 8);
    }
    for (int i = 0; i < init_loop; ++i) {
        shift128plus_next(ctx);
    }
}
