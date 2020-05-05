/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2018, Akkariiin
 */

#ifndef _OBFS_AUTH_AKARIN_H
#define _OBFS_AUTH_AKARIN_H

#include "obfs.h"


void *auth_akarin_rand_init_data();

void *auth_akarin_spec_a_init_data();


obfs *auth_akarin_rand_new_obfs();

obfs *auth_akarin_spec_a_new_obfs();


void auth_akarin_rand_dispose(obfs *self);

void auth_akarin_spec_a_dispose(obfs *self);


void auth_akarin_rand_set_server_info(obfs *self, server_info *server);

void auth_akarin_spec_a_set_server_info(obfs *self, server_info *server);



int auth_akarin_rand_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_akarin_rand_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_akarin_rand_client_udp_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);

int auth_akarin_rand_client_udp_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t *capacity);


int auth_akarin_rand_get_overhead(obfs *self);

int auth_akarin_spec_a_get_overhead(obfs *self);



#endif // _OBFS_AUTH_AKARIN_H
