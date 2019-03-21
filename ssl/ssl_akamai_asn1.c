/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "ssl_locl.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

/*
 * This structure represents the data in an SSL object that needs to
 * be serialized. If it is not in this structure, then it is reset
 * upon deserialization.
 * Some SSL object fields will be initialized from an SSL_CTX.
 */

/* Update when the SSL structure becomes sufficiently incompatible */
#define SSL_AKAMAI_ASN1_VERSION 0x00000001

/* These are the bit field definitions, they are internal to this, the caller should set the bits */
/* These are used as indices in the ASN.1 representation - limited to values below 64 */
#define HOSTNAME_BIT                      0
#define ECPOINTFORMATS_BIT                1
#define SUPPORTEDGROUPS_BIT               2
#define ALPN_BIT                          3
#define ALPN_PROPOSED_BIT                 4
#define EARLY_SECRET_BIT                  5
#define HANDSHAKE_SECRET_BIT              6
#define CLIENT_FINISHED_SECRET_BIT        7
#define SERVER_FINISHED_SECRET_BIT        8
#define SERVER_FINISHED_HASH_BIT          9
#define HANDSHAKE_TRAFFIC_HASH_BIT       10
#define EXPORTER_MASTER_SECRET_BIT       11
#define EARLY_EXPORTER_MASTER_SECRET_BIT 12
#define EX_DATA_SERVER_RANDOM_BIT        13
#define SESSION_PEER_BIT                 14
#define PRIVATE_KEY_BIT                  15
#define READ_MAC_SECRET_BIT              16
#define WRITE_MAC_SECRET_BIT             17

#define BIT_IS_SET(field, bit) !!((field) & (1 << (bit)))

typedef struct {
    uint32_t struct_version;
    int32_t version;
    int32_t client_version;
    int32_t server;
    int32_t hit;
    uint32_t cipher_id;
    uint32_t mac_flags;
    ASN1_OCTET_STRING *early_secret;
    ASN1_OCTET_STRING *handshake_secret;
    ASN1_OCTET_STRING *master_secret;
    ASN1_OCTET_STRING *resumption_master_secret;
    ASN1_OCTET_STRING *client_finished_secret;
    ASN1_OCTET_STRING *server_finished_secret;
    ASN1_OCTET_STRING *server_finished_hash;
    ASN1_OCTET_STRING *handshake_traffic_hash;
    ASN1_OCTET_STRING *client_app_traffic_secret;
    ASN1_OCTET_STRING *server_app_traffic_secret;
    ASN1_OCTET_STRING *exporter_master_secret;
    ASN1_OCTET_STRING *early_exporter_master_secret;
    /* read_iv and write_iv not needed */
    /* sid_ctx not needed */
    int64_t verify_result;
    uint32_t options;
    uint32_t mode;
    int32_t min_proto_version;
    int32_t max_proto_version;
    ASN1_OCTET_STRING *hostname;
    ASN1_OCTET_STRING *ecpointformats;
    ASN1_OCTET_STRING *supportedgroups;
    ASN1_OCTET_STRING *alpn;
    int32_t psk_kex_mode;
    int32_t use_etm;
    uint32_t max_fragment_len_mode;
    int32_t servername_done;
    uint64_t num_tickets;
    uint64_t sent_tickets;
    uint64_t next_ticket_nonce;
    uint32_t post_handshake_auth;
    /* rlayer elements */
    ASN1_OCTET_STRING *rlayer_read_sequence;
    ASN1_OCTET_STRING *rlayer_write_sequence;
    /* s3 elements */
    int64_t s3_flags;
    ASN1_OCTET_STRING *s3_read_mac_secret;
    ASN1_OCTET_STRING *s3_write_mac_secret;
    ASN1_OCTET_STRING *s3_server_random;
    ASN1_OCTET_STRING *s3_client_random;
    ASN1_OCTET_STRING *s3_previous_client_finished;
    ASN1_OCTET_STRING *s3_previous_server_finished;
    int32_t s3_send_connection_binding;
    ASN1_OCTET_STRING *s3_alpn_selected;
    ASN1_OCTET_STRING *s3_alpn_proposed;
    int32_t s3_alpn_sent;
    /* statem elements */
    uint32_t statem_state;
    uint32_t statem_write_state;
    uint32_t statem_write_state_work;
    uint32_t statem_read_state;
    uint32_t statem_read_state_work;
    uint32_t statem_hand_state;
    uint32_t statem_request_state;
    uint32_t statem_in_init;
    uint32_t statem_read_state_first_init;
    uint32_t statem_in_handshake;
    uint32_t statem_cleanuphand;
    uint32_t statem_use_timer;
    uint32_t statem_enc_write_state;
    uint32_t statem_enc_read_state;
    /* session elements */
    ASN1_OCTET_STRING *session_master_key;
    ASN1_OCTET_STRING *session_session_id;
    ASN1_OCTET_STRING *session_ext_tick;
    uint32_t session_flags;
    /* enc_{read|write}_ctx for TLSv1/SSLv3 */
    ASN1_OCTET_STRING *enc_read_ctx_iv;
    ASN1_OCTET_STRING *enc_write_ctx_iv;
    ASN1_OCTET_STRING *s3_tmp_peer_finish_md;
    ASN1_OCTET_STRING *s3_tmp_finish_md;
    /* Akamai EX_DATA */
    uint32_t ex_data_options;
    ASN1_OCTET_STRING *ex_data_server_random;
    X509 *session_peer;
    X509 *cert_key_x509;
    ASN1_OCTET_STRING *private_key;
    ASN1_OCTET_STRING *session_ticket_appdata;
    int32_t s3_tmp_peer_sigalg_sigalg;
    ASN1_OCTET_STRING *s3_peer_tmp;
    int32_t s3_peer_tmp_type;
    int32_t s3_peer_tmp_group;
} SSL_AKAMAI_ASN1;

ASN1_SEQUENCE(SSL_AKAMAI_ASN1) = {
    /* MANDATORY NUMERIC FIELDS */
    ASN1_EMBED(SSL_AKAMAI_ASN1, struct_version, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, version, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, client_version, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, server, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, hit, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, cipher_id, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, verify_result, INT64),
    ASN1_EMBED(SSL_AKAMAI_ASN1, options, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, use_etm, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, max_fragment_len_mode, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_flags, INT64),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_send_connection_binding, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_hand_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_in_init, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_enc_write_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_enc_read_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, ex_data_options, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, session_flags, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_tmp_peer_sigalg_sigalg, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_peer_tmp_type, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_peer_tmp_group, INT32),
    /* OPTIONAL NUMERIC FIELDS -- but we always send them */
    ASN1_EMBED(SSL_AKAMAI_ASN1, mac_flags, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, mode, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, min_proto_version, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, max_proto_version, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, psk_kex_mode, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, servername_done, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, num_tickets, UINT64),
    ASN1_EMBED(SSL_AKAMAI_ASN1, sent_tickets, UINT64),
    ASN1_EMBED(SSL_AKAMAI_ASN1, next_ticket_nonce, UINT64),
    ASN1_EMBED(SSL_AKAMAI_ASN1, post_handshake_auth, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, s3_alpn_sent, INT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_write_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_write_state_work, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_read_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_read_state_work, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_request_state, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_read_state_first_init, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_in_handshake, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_cleanuphand, UINT32),
    ASN1_EMBED(SSL_AKAMAI_ASN1, statem_use_timer, UINT32),
    /* MANDATORY DATA FIELDS */
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, rlayer_read_sequence, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, rlayer_write_sequence, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, s3_server_random, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, s3_client_random, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, s3_previous_client_finished, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, s3_previous_server_finished, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_AKAMAI_ASN1, session_master_key, ASN1_OCTET_STRING),
    /* OPTIONAL DATA FIELDS - USE _BIT DEFINITION 0-63 */
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, hostname, ASN1_OCTET_STRING, HOSTNAME_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, ecpointformats, ASN1_OCTET_STRING, ECPOINTFORMATS_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, supportedgroups, ASN1_OCTET_STRING, SUPPORTEDGROUPS_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, alpn, ASN1_OCTET_STRING, ALPN_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_alpn_proposed, ASN1_OCTET_STRING, ALPN_PROPOSED_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, early_secret, ASN1_OCTET_STRING, EARLY_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, handshake_secret, ASN1_OCTET_STRING, HANDSHAKE_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, client_finished_secret, ASN1_OCTET_STRING, CLIENT_FINISHED_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, server_finished_secret, ASN1_OCTET_STRING, SERVER_FINISHED_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, server_finished_hash, ASN1_OCTET_STRING, SERVER_FINISHED_HASH_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, handshake_traffic_hash, ASN1_OCTET_STRING, HANDSHAKE_TRAFFIC_HASH_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, exporter_master_secret, ASN1_OCTET_STRING, EXPORTER_MASTER_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, early_exporter_master_secret, ASN1_OCTET_STRING, EARLY_EXPORTER_MASTER_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, ex_data_server_random, ASN1_OCTET_STRING, EX_DATA_SERVER_RANDOM_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, session_peer, X509, SESSION_PEER_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, private_key, ASN1_OCTET_STRING, PRIVATE_KEY_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_read_mac_secret, ASN1_OCTET_STRING, READ_MAC_SECRET_BIT),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_write_mac_secret, ASN1_OCTET_STRING, WRITE_MAC_SECRET_BIT),
    /* MANDATORY DATA FIELDS FOR SOME PROTOCOLS 100-199 */
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, master_secret, ASN1_OCTET_STRING, 100),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, resumption_master_secret, ASN1_OCTET_STRING, 101),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, client_app_traffic_secret, ASN1_OCTET_STRING, 102),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, server_app_traffic_secret, ASN1_OCTET_STRING, 103),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, session_ext_tick, ASN1_OCTET_STRING, 104),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, session_ticket_appdata, ASN1_OCTET_STRING, 105),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, enc_read_ctx_iv, ASN1_OCTET_STRING, 106),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, enc_write_ctx_iv, ASN1_OCTET_STRING, 107),
    /* MANDATORY DATA FIELDS BUT MAY BE NULL 200-255 */
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, cert_key_x509, X509, 200),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_peer_tmp, ASN1_OCTET_STRING, 201),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, session_session_id, ASN1_OCTET_STRING, 202),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_alpn_selected, ASN1_OCTET_STRING, 203),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_tmp_finish_md, ASN1_OCTET_STRING, 204),
    ASN1_EXP_OPT(SSL_AKAMAI_ASN1, s3_tmp_peer_finish_md, ASN1_OCTET_STRING, 205),
} static_ASN1_SEQUENCE_END(SSL_AKAMAI_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(SSL_AKAMAI_ASN1)

/* Utility functions for i2d_SSL_AKAMAI */

/* Initialise OCTET STRING from buffer and length */
static void ssl_akamai_oinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                             unsigned char *data, size_t len)
{
    os->data = data;
    os->length = (int)len;
    os->flags = 0;
    *dest = os;
}

/* Initialise OCTET STRING from string */
static void ssl_akamai_sinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                             char *data)
{
    if (data != NULL)
        ssl_akamai_oinit(dest, os, (unsigned char *)data, strlen(data));
    else
        *dest = NULL;
}

int i2d_SSL_AKAMAI(SSL *in, unsigned char **pp, uint64_t options)
{
    SSL_AKAMAI_ASN1 as;
    SSL_EX_DATA_AKAMAI *ex_data;
    int ret;

    ASN1_OCTET_STRING early_secret;
    ASN1_OCTET_STRING handshake_secret;
    ASN1_OCTET_STRING master_secret;
    ASN1_OCTET_STRING resumption_master_secret;
    ASN1_OCTET_STRING client_finished_secret;
    ASN1_OCTET_STRING server_finished_secret;
    ASN1_OCTET_STRING server_finished_hash;
    ASN1_OCTET_STRING handshake_traffic_hash;
    ASN1_OCTET_STRING client_app_traffic_secret;
    ASN1_OCTET_STRING server_app_traffic_secret;
    ASN1_OCTET_STRING exporter_master_secret;
    ASN1_OCTET_STRING early_exporter_master_secret;
    ASN1_OCTET_STRING hostname;
    ASN1_OCTET_STRING ecpointformats;
    ASN1_OCTET_STRING supportedgroups;
    ASN1_OCTET_STRING alpn;
    ASN1_OCTET_STRING rlayer_read_sequence;
    ASN1_OCTET_STRING rlayer_write_sequence;
    ASN1_OCTET_STRING s3_read_mac_secret;
    ASN1_OCTET_STRING s3_write_mac_secret;
    ASN1_OCTET_STRING s3_server_random;
    ASN1_OCTET_STRING s3_client_random;
    ASN1_OCTET_STRING s3_previous_client_finished;
    ASN1_OCTET_STRING s3_previous_server_finished;
    ASN1_OCTET_STRING s3_alpn_selected;
    ASN1_OCTET_STRING s3_alpn_proposed;
    ASN1_OCTET_STRING session_master_key;
    ASN1_OCTET_STRING session_session_id;
    ASN1_OCTET_STRING enc_read_ctx_iv;
    ASN1_OCTET_STRING enc_write_ctx_iv;
    ASN1_OCTET_STRING s3_tmp_finish_md;
    ASN1_OCTET_STRING s3_tmp_peer_finish_md;
    ASN1_OCTET_STRING ex_data_server_random;
    ASN1_OCTET_STRING session_ext_tick;
    ASN1_OCTET_STRING private_key = { 0, 0, 0 };
    ASN1_OCTET_STRING session_ticket_appdata;
    ASN1_OCTET_STRING s3_peer_tmp = { 0, 0, 0 };

    if (in == NULL)
        return -1;
    if (!SSL_is_init_finished(in))
        return -2;
    if (in->s3->in_read_app_data != 0)
        return -3;
    if (in->s3->fatal_alert != 0)
        return -4;
    if (in->s3->send_alert[0] == SSL3_AL_FATAL)
        return -5;
    if (in->session == NULL)
        return -6;
    if (in->session->cipher == NULL)
        return -7;
    if ((ex_data = SSL_get_ex_data_akamai(in)) == NULL)
        return -8;
    if (in->statem.hand_state != TLS_ST_OK)
        return -9;
    if (SSL_waiting_for_async(in))
        return -10;

    memset(&as, 0, sizeof(as));

    /* MANDATORY NUMERIC FIELDS - REQUIRED FOR UNIT TESTS */
    as.struct_version = SSL_AKAMAI_ASN1_VERSION;
    as.version = in->method->version;
    as.client_version = in->client_version;
    as.server = in->server;
    as.hit = in->hit;
    as.cipher_id = in->session->cipher->id;
    as.options = in->options;
    as.use_etm = in->ext.use_etm;
    as.max_fragment_len_mode = in->session->ext.max_fragment_len_mode;
    as.num_tickets = in->num_tickets;
    as.s3_send_connection_binding = in->s3->send_connection_binding;
    as.statem_state = in->statem.state;
    as.statem_hand_state = in->statem.hand_state;
    as.statem_in_init = in->statem.in_init;
    as.statem_enc_write_state = in->statem.enc_write_state;
    as.statem_enc_read_state = in->statem.enc_read_state;
    as.session_flags = in->session->flags;
    as.session_peer = in->session->peer;
    as.s3_tmp_peer_sigalg_sigalg = tls1_akamai_get_peer_sigalg(in);
    as.s3_flags = in->s3->flags;
    as.verify_result = in->verify_result;

    /* OPTIONAL NUMERIC FIELDS - BUT WE ALWAYS SEND */
    as.mode = in->mode;
    as.psk_kex_mode = in->ext.psk_kex_mode;
    as.post_handshake_auth = in->post_handshake_auth;
    as.mac_flags = in->mac_flags;
    as.min_proto_version = in->min_proto_version;
    as.max_proto_version = in->max_proto_version;
    as.servername_done = in->servername_done;
    as.sent_tickets = in->sent_tickets;
    as.next_ticket_nonce = in->next_ticket_nonce;
    as.s3_alpn_sent = in->s3->alpn_sent;
    as.statem_write_state = in->statem.write_state;
    as.statem_write_state_work = in->statem.write_state_work;
    as.statem_read_state = in->statem.read_state;
    as.statem_read_state_work = in->statem.read_state_work;
    as.statem_request_state = in->statem.request_state;
    as.statem_read_state_first_init = in->statem.read_state_first_init;
    as.statem_in_handshake = in->statem.in_handshake;
    as.statem_cleanuphand = in->statem.cleanuphand;
    as.statem_use_timer = in->statem.use_timer;

    /* MANDATORY DATA FIELDS */
    ssl_akamai_oinit(&as.s3_server_random, &s3_server_random,
                     in->s3->server_random, SSL3_RANDOM_SIZE);
    ssl_akamai_oinit(&as.s3_client_random, &s3_client_random,
                     in->s3->client_random, SSL3_RANDOM_SIZE);
    ssl_akamai_oinit(&as.rlayer_read_sequence, &rlayer_read_sequence,
                     in->rlayer.read_sequence, sizeof(in->rlayer.read_sequence));
    ssl_akamai_oinit(&as.rlayer_write_sequence, &rlayer_write_sequence,
                     in->rlayer.write_sequence, sizeof(in->rlayer.write_sequence));
    ssl_akamai_oinit(&as.s3_previous_client_finished, &s3_previous_client_finished,
                     in->s3->previous_client_finished, in->s3->previous_client_finished_len);
    ssl_akamai_oinit(&as.s3_previous_server_finished, &s3_previous_server_finished,
                     in->s3->previous_server_finished, in->s3->previous_server_finished_len);
    ssl_akamai_oinit(&as.session_master_key, &session_master_key,
                     in->session->master_key, in->session->master_key_length);

    /* MANDATORY DATA FIELDS - BUT ONLY REQUIRED FOR SOME PROTOCOLS */
    if (in->version == TLS1_3_VERSION) {
        ssl_akamai_oinit(&as.master_secret, &master_secret,
                         in->master_secret, sizeof(in->master_secret));
        ssl_akamai_oinit(&as.resumption_master_secret, &resumption_master_secret,
                         in->resumption_master_secret, sizeof(in->resumption_master_secret));
        ssl_akamai_oinit(&as.server_finished_hash, &server_finished_hash,
                         in->server_finished_hash, sizeof(in->server_finished_hash));
        ssl_akamai_oinit(&as.client_app_traffic_secret, &client_app_traffic_secret,
                         in->client_app_traffic_secret, sizeof(in->client_app_traffic_secret));
        ssl_akamai_oinit(&as.server_app_traffic_secret, &server_app_traffic_secret,
                         in->server_app_traffic_secret, sizeof(in->server_app_traffic_secret));
    }
    if (as.version == SSL3_VERSION || as.version == TLS1_VERSION) {
        ssl_akamai_oinit(&as.enc_read_ctx_iv, &enc_read_ctx_iv,
                         EVP_CIPHER_CTX_iv_noconst(in->enc_read_ctx),
                         EVP_CIPHER_CTX_iv_length(in->enc_read_ctx));
        ssl_akamai_oinit(&as.enc_write_ctx_iv, &enc_write_ctx_iv,
                         EVP_CIPHER_CTX_iv_noconst(in->enc_write_ctx),
                         EVP_CIPHER_CTX_iv_length(in->enc_write_ctx));
    }
    if (!in->server && in->session->ext.ticklen != 0 && in->session->ext.tick != NULL)
        ssl_akamai_oinit(&as.session_ext_tick, &session_ext_tick,
                         in->session->ext.tick, in->session->ext.ticklen);

    if (in->session->ticket_appdata_len != 0 && in->session->ticket_appdata != NULL)
        ssl_akamai_oinit(&as.session_ticket_appdata, &session_ticket_appdata,
                         in->session->ticket_appdata, in->session->ticket_appdata_len);

    /* MANDATORY DATA FIELDS - BUT MAY BE NULL/EMPTY */
    if (in->s3->peer_tmp != NULL) {
        s3_peer_tmp.length = i2d_PublicKey(in->s3->peer_tmp, &s3_peer_tmp.data);
        if (s3_peer_tmp.length > 0) {
            as.s3_peer_tmp_type = EVP_PKEY_id(in->s3->peer_tmp);
            if (as.s3_peer_tmp_type == EVP_PKEY_EC)
                as.s3_peer_tmp_group = EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(in->s3->peer_tmp)));
            as.s3_peer_tmp = &s3_peer_tmp;
        } else {
            /* skip key if error - usuaually unsupported type - X25519 or X448 */
            ERR_clear_error();
        }
    }
    if (in->session->session_id_length != 0)
        ssl_akamai_oinit(&as.session_session_id, &session_session_id,
                         in->session->session_id, in->session->session_id_length);

    if (in->s3->alpn_selected != NULL)
        ssl_akamai_oinit(&as.s3_alpn_selected, &s3_alpn_selected,
                         in->s3->alpn_selected, in->s3->alpn_selected_len);

    if (in->s3->tmp.peer_finish_md_len != 0)
        ssl_akamai_oinit(&as.s3_tmp_peer_finish_md, &s3_tmp_peer_finish_md,
                         in->s3->tmp.peer_finish_md, in->s3->tmp.peer_finish_md_len);

    if (in->s3->tmp.finish_md_len != 0)
        ssl_akamai_oinit(&as.s3_tmp_finish_md, &s3_tmp_finish_md,
                         in->s3->tmp.finish_md, in->s3->tmp.finish_md_len);

    /* OPTIONAL */
    if (BIT_IS_SET(options, PRIVATE_KEY_BIT)) {
        if (in->cert->key != NULL) {
            as.cert_key_x509 = in->cert->key->x509;

            if (in->cert->key->privatekey != NULL) {
                private_key.length = i2d_PrivateKey(in->cert->key->privatekey,
                                                    &private_key.data);
                if (private_key.length != 0)
                    as.private_key = &private_key;
            }
        }
    }

    if (in->version == TLS1_3_VERSION) {
        if (BIT_IS_SET(options, EARLY_SECRET_BIT))
            ssl_akamai_oinit(&as.early_secret, &early_secret,
                             in->early_secret, sizeof(in->early_secret));
        if (BIT_IS_SET(options, HANDSHAKE_SECRET_BIT))
            ssl_akamai_oinit(&as.handshake_secret, &handshake_secret,
                             in->handshake_secret, sizeof(in->handshake_secret));
        if (BIT_IS_SET(options, CLIENT_FINISHED_SECRET_BIT))
            ssl_akamai_oinit(&as.client_finished_secret, &client_finished_secret,
                             in->client_finished_secret, sizeof(in->client_finished_secret));
        if (BIT_IS_SET(options, SERVER_FINISHED_SECRET_BIT))
            ssl_akamai_oinit(&as.server_finished_secret, &server_finished_secret,
                             in->server_finished_secret, sizeof(in->server_finished_secret));
        if (BIT_IS_SET(options, HANDSHAKE_TRAFFIC_HASH_BIT))
            ssl_akamai_oinit(&as.handshake_traffic_hash, &handshake_traffic_hash,
                             in->handshake_traffic_hash, sizeof(in->handshake_traffic_hash));
        if (BIT_IS_SET(options, EXPORTER_MASTER_SECRET_BIT))
            ssl_akamai_oinit(&as.exporter_master_secret, &exporter_master_secret,
                             in->exporter_master_secret, sizeof(in->exporter_master_secret));
        if (BIT_IS_SET(options, EARLY_EXPORTER_MASTER_SECRET_BIT))
            ssl_akamai_oinit(&as.early_exporter_master_secret, &early_exporter_master_secret,
                             in->early_exporter_master_secret, sizeof(in->early_exporter_master_secret));
    }
    if (BIT_IS_SET(options, READ_MAC_SECRET_BIT))
        ssl_akamai_oinit(&as.s3_read_mac_secret, &s3_read_mac_secret,
                         in->s3->read_mac_secret, in->s3->read_mac_secret_size);
    if (BIT_IS_SET(options, WRITE_MAC_SECRET_BIT))
        ssl_akamai_oinit(&as.s3_write_mac_secret, &s3_write_mac_secret,
                         in->s3->write_mac_secret, in->s3->write_mac_secret_size);

    if (BIT_IS_SET(options, HOSTNAME_BIT))
        ssl_akamai_sinit(&as.hostname, &hostname, in->ext.hostname);

#ifndef OPENSSL_NO_EC
    if (BIT_IS_SET(options, ECPOINTFORMATS_BIT) && in->ext.ecpointformats != NULL)
        ssl_akamai_oinit(&as.ecpointformats, &ecpointformats,
                         (unsigned char*)in->ext.ecpointformats,
                         in->ext.ecpointformats_len);
#endif

    if (BIT_IS_SET(options, SUPPORTEDGROUPS_BIT) && in->ext.supportedgroups != NULL)
        ssl_akamai_oinit(&as.supportedgroups, &supportedgroups,
                         (unsigned char*)in->ext.supportedgroups,
                         in->ext.supportedgroups_len);

    if (BIT_IS_SET(options, ALPN_BIT) && in->ext.alpn != NULL)
        ssl_akamai_oinit(&as.alpn, &alpn, in->ext.alpn, in->ext.alpn_len);

    if (BIT_IS_SET(options, ALPN_PROPOSED_BIT) && in->s3->alpn_proposed != NULL)
        ssl_akamai_oinit(&as.s3_alpn_proposed, &s3_alpn_proposed,
                         in->s3->alpn_proposed, in->s3->alpn_proposed_len);

    if (BIT_IS_SET(options, EX_DATA_SERVER_RANDOM_BIT)) {
        as.ex_data_options = ex_data->options;
        ssl_akamai_oinit(&as.ex_data_server_random, &ex_data_server_random,
                         ex_data->server_random, sizeof(ex_data->server_random));
    }

    ret = i2d_SSL_AKAMAI_ASN1(&as, pp);
    OPENSSL_free(private_key.data);
    OPENSSL_free(s3_peer_tmp.data);
    return ret;
}

/* Utility functions for d2i_SSL_AKAMAI */

/* OPENSSL_strndup an OCTET STRING */
static int ssl_akamai_strndup(char **pdst, ASN1_OCTET_STRING *src)
{
    OPENSSL_free(*pdst);
    *pdst = NULL;
    if (src == NULL)
        return 1;
    *pdst = OPENSSL_strndup((char *)src->data, src->length);
    if (*pdst == NULL)
        return 0;
    return 1;
}

/* OPENSSL_memdup an OCTET STRING */
static int ssl_akamai_memdup(unsigned char **pdst, size_t *len, ASN1_OCTET_STRING *src)
{
    OPENSSL_free(*pdst);
    *pdst = NULL;
    if (src == NULL)
        return 1;
    *pdst = OPENSSL_memdup(src->data, src->length);
    if (*pdst == NULL)
        return 0;
    *len = src->length;
    return 1;
}

/* Copy an OCTET STRING, return error if it exceeds maximum length */
static int ssl_akamai_memcpy(unsigned char *dst, size_t *pdstlen,
                             ASN1_OCTET_STRING *src, size_t maxlen)
{
    if (src == NULL) {
        if (pdstlen != NULL)
            *pdstlen = 0;
        return 1;
    }
    if (src->length < 0 || src->length > (int)maxlen)
        return 0;
    memcpy(dst, src->data, src->length);
    if (pdstlen != NULL)
        *pdstlen = src->length;
    return 1;
}

SSL *d2i_SSL_AKAMAI(SSL **a, SSL_CTX* ctx, const unsigned char **pp,
                    long length)
{
    size_t tmpl;
    const unsigned char *p = *pp;
    SSL_AKAMAI_ASN1 *as = NULL;
    SSL *ret = NULL;
    const SSL_METHOD *meth;
    int rd_flags, wr_flags;
    SSL_EX_DATA_AKAMAI *ex_data;
    EVP_PKEY *pkey = NULL;

    as = d2i_SSL_AKAMAI_ASN1(NULL, &p, length);
    /* ASN.1 code returns suitable error */
    if (as == NULL)
        goto err;

    if (a == NULL || *a == NULL) {
        ret = SSL_new(ctx);
        if (ret == NULL)
            goto err;
    } else {
        ret = *a;
    }

    if (as->struct_version != SSL_AKAMAI_ASN1_VERSION) {
        SSLerr(SSL_F_D2I_SSL_AKAMAI, SSL_R_UNKNOWN_SSL_VERSION);
        goto err;
    }

    switch (as->version) {
#ifndef OPENSSL_NO_DTLS1
        case DTLS1_BAD_VER:
            if (as->server)
                goto err;
            else
                meth = dtls_bad_ver_client_method();
            break;
        case DTLS1_VERSION:
            if (as->server)
                meth = dtlsv1_server_method();
            else
                meth = dtlsv1_client_method();
            break;
#endif
#ifndef OPENSSL_NO_DTLS1_2
        case DTLS1_2_VERSION:
            if (as->server)
                meth = dtlsv1_2_server_method();
            else
                meth = dtlsv1_2_client_method();
            break;
#endif
#ifndef OPENSSL_NO_SSL3
        case SSL3_VERSION:
            if (as->server)
                meth = sslv3_server_method();
            else
                meth = sslv3_client_method();
            break;
#endif
#ifndef OPENSSL_NO_TLS1
        case TLS1_VERSION:
            if (as->server)
                meth = tlsv1_server_method();
            else
                meth = tlsv1_client_method();
            break;
#endif
#ifndef OPENSSL_NO_TLS1_1
        case TLS1_1_VERSION:
            if (as->server)
                meth = tlsv1_1_server_method();
            else
                meth = tlsv1_1_client_method();
            break;
#endif
#ifndef OPENSSL_NO_TLS1_2
        case TLS1_2_VERSION:
            if (as->server)
                meth = tlsv1_2_server_method();
            else
                meth = tlsv1_2_client_method();
            break;
#endif
#ifndef OPENSSL_NO_TLS1_3
        case TLS1_3_VERSION:
            if (as->server)
                meth = tlsv1_3_server_method();
            else
                meth = tlsv1_3_client_method();
            break;
#endif
        default:
            SSLerr(SSL_F_D2I_SSL_AKAMAI, SSL_R_UNSUPPORTED_SSL_VERSION);
            goto err;
    }

    ret->version = as->version;
    ret->client_version = as->client_version;
    ret->server = as->server;
    if (!SSL_set_ssl_method(ret, meth))
        goto err;
    ret->handshake_func = ret->server ? ret->method->ssl_accept : ret->method->ssl_connect;
    ret->hit = as->hit;

    if (!ssl3_init_finished_mac(ret))
        goto err;

    /* no need for a session id, so session=0 */
    if (!ssl_get_new_session(ret, 0))
        goto err;

    ret->session->cipher_id = as->cipher_id;
    ret->session->cipher = ssl3_get_cipher_by_id(as->cipher_id);
    ret->session->ssl_version = ret->version;
    ret->session->not_resumable = 0;
    ret->session->flags = as->session_flags;
    if (ret->session->cipher == NULL) {
        SSLerr(SSL_F_D2I_SSL_AKAMAI, SSL_R_UNKNOWN_CIPHER_TYPE);
        goto err;
    }
    SSL_CTX_add_session(ret->session_ctx, ret->session);
    ret->s3->tmp.new_cipher = ret->session->cipher;
    ret->ext.use_etm = as->use_etm;
    ret->ext.max_fragment_len_mode = as->max_fragment_len_mode;
    ret->session->ext.max_fragment_len_mode = as->max_fragment_len_mode;
    ret->s3->send_connection_binding = as->s3_send_connection_binding;
    ret->s3->flags = as->s3_flags;
    ret->statem.state = as->statem_state;
    ret->statem.hand_state = as->statem_hand_state;
    ret->statem.in_init = as->statem_in_init;
    ret->statem.enc_read_state = as->statem_enc_read_state;
    ret->s3->tmp.peer_sigalg = tls1_akamai_lookup_sigalg(as->s3_tmp_peer_sigalg_sigalg);
    ret->statem.enc_write_state = as->statem_enc_write_state;
    ret->verify_result = as->verify_result;
    ret->options = as->options;

    /* THESE ARE OPTIONAL FIELDS - BUT SENT ANYWAYS */
    ret->mac_flags = as->mac_flags;
    ret->mode = as->mode;
    ret->min_proto_version = as->min_proto_version;
    ret->max_proto_version = as->max_proto_version;
    ret->ext.psk_kex_mode = as->psk_kex_mode;
    ret->servername_done = as->servername_done;
    ret->num_tickets = as->num_tickets;
    ret->sent_tickets = as->sent_tickets;
    ret->next_ticket_nonce = as->next_ticket_nonce;
    ret->post_handshake_auth = as->post_handshake_auth;
    ret->s3->alpn_sent = as->s3_alpn_sent;
    ret->statem.write_state = as->statem_write_state;
    ret->statem.write_state_work = as->statem_write_state_work;
    ret->statem.read_state = as->statem_read_state;
    ret->statem.read_state_work = as->statem_read_state_work;
    ret->statem.request_state = as->statem_request_state;
    ret->statem.read_state_first_init = as->statem_read_state_first_init;
    ret->statem.in_handshake = as->statem_in_handshake;
    ret->statem.cleanuphand = as->statem_cleanuphand;
    ret->statem.use_timer = as->statem_use_timer;
    /* END OPTIONAL FIELDS */

    if (as->s3_peer_tmp != NULL) {
        const unsigned char *tmp = as->s3_peer_tmp->data;
        EVP_PKEY *peer_pkey = NULL;
        EC_KEY *ec = NULL;

        if (as->s3_peer_tmp_type == EVP_PKEY_EC) {
            peer_pkey = EVP_PKEY_new();
            if (peer_pkey == NULL)
                goto err;
            ec = EC_KEY_new_by_curve_name(as->s3_peer_tmp_group);
            if (ec == NULL) {
                EVP_PKEY_free(peer_pkey);
                goto err;
            }
            if (!EVP_PKEY_assign_EC_KEY(peer_pkey, ec)) {
                EVP_PKEY_free(peer_pkey);
                peer_pkey = NULL;
                EC_KEY_free(ec);
                ec = NULL;
                goto err;
            }
        }

        ret->s3->peer_tmp = d2i_PublicKey(as->s3_peer_tmp_type, &peer_pkey, &tmp, as->s3_peer_tmp->length);
        if (ret->s3->peer_tmp == NULL) {
            EVP_PKEY_free(peer_pkey);
            goto err;
        }
    }

    if (!ssl_akamai_memcpy(ret->master_secret, NULL,
                           as->master_secret, sizeof(ret->master_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->resumption_master_secret, NULL,
                           as->resumption_master_secret, sizeof(ret->resumption_master_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->server_finished_hash, NULL,
                           as->server_finished_hash, sizeof(ret->server_finished_hash)))
        goto err;
    if (!ssl_akamai_memcpy(ret->client_app_traffic_secret, NULL,
                           as->client_app_traffic_secret, sizeof(ret->client_app_traffic_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->server_app_traffic_secret, NULL,
                           as->server_app_traffic_secret, sizeof(ret->server_app_traffic_secret)))
        goto err;

    /* OPTIONAL */
    X509_free(ret->session->peer);
    ret->session->peer = as->session_peer;
    as->session_peer = NULL;

    if (as->cert_key_x509 != NULL) {
        if (as->private_key != NULL) {
            const unsigned char *tmp = as->private_key->data;

            pkey = d2i_AutoPrivateKey(NULL, &tmp, as->private_key->length);
        }
        if (!SSL_use_cert_and_key(ret, as->cert_key_x509, pkey, NULL, 1))
            goto err;
        ret->s3->tmp.cert = ret->cert->key;
    }
    if (!ssl_akamai_memcpy(ret->early_secret, NULL,
                           as->early_secret, sizeof(ret->early_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->handshake_secret, NULL,
                           as->handshake_secret, sizeof(ret->handshake_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->client_finished_secret, NULL,
                           as->client_finished_secret, sizeof(ret->client_finished_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->server_finished_secret, NULL,
                           as->server_finished_secret, sizeof(ret->server_finished_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->handshake_traffic_hash, NULL,
                           as->handshake_traffic_hash, sizeof(ret->handshake_traffic_hash)))
        goto err;
    if (!ssl_akamai_memcpy(ret->exporter_master_secret, NULL,
                           as->exporter_master_secret, sizeof(ret->exporter_master_secret)))
        goto err;
    if (!ssl_akamai_memcpy(ret->early_exporter_master_secret, NULL,
                           as->early_exporter_master_secret, sizeof(ret->early_exporter_master_secret)))
        goto err;

    if (!ssl_akamai_memcpy(ret->s3->read_mac_secret, &tmpl,
                           as->s3_read_mac_secret, sizeof(ret->s3->read_mac_secret)))
        goto err;
    ret->s3->read_mac_secret_size = tmpl;

    if (!ssl_akamai_memcpy(ret->s3->write_mac_secret, &tmpl,
                           as->s3_write_mac_secret, sizeof(ret->s3->write_mac_secret)))
        goto err;
    ret->s3->write_mac_secret_size = tmpl;

    if (!ssl_akamai_strndup(&ret->ext.hostname, as->hostname))
        goto err;

#ifndef OPENSSL_NO_EC
    if (!ssl_akamai_memdup((unsigned char**)&ret->ext.ecpointformats,
                           &tmpl, as->ecpointformats))
        goto err;
    if (ret->ext.ecpointformats != NULL)
        ret->ext.ecpointformats_len = tmpl;
#endif

    if (!ssl_akamai_memdup((unsigned char**)&ret->ext.supportedgroups,
                           &tmpl, as->supportedgroups))
        goto err;
    if (ret->ext.supportedgroups != NULL)
        ret->ext.supportedgroups_len = tmpl;

    if (!ssl_akamai_memdup((unsigned char**)&ret->ext.alpn, &tmpl, as->alpn))
        goto err;
    if (ret->ext.alpn != NULL)
        ret->ext.alpn_len = tmpl;

    if (!ssl_akamai_memdup((unsigned char**)&ret->s3->alpn_proposed, &tmpl, as->s3_alpn_proposed))
        goto err;
    if (ret->s3->alpn_proposed != NULL)
        ret->s3->alpn_proposed_len = tmpl;
    /* END OPTIONAL */

    if (!ssl_akamai_memcpy(ret->s3->server_random, NULL,
                           as->s3_server_random, sizeof(ret->s3->server_random)))
        goto err;

    if (!ssl_akamai_memcpy(ret->s3->client_random, NULL,
                           as->s3_client_random, sizeof(ret->s3->client_random)))
        goto err;

    if (!ssl_akamai_memcpy(ret->s3->previous_client_finished, &tmpl,
                           as->s3_previous_client_finished, sizeof(ret->s3->previous_client_finished)))
        goto err;
    ret->s3->previous_client_finished_len = tmpl;

    if (!ssl_akamai_memcpy(ret->s3->previous_server_finished, &tmpl,
                           as->s3_previous_server_finished, sizeof(ret->s3->previous_server_finished)))
        goto err;
    ret->s3->previous_server_finished_len = tmpl;

    if (!ssl_akamai_memcpy(ret->session->master_key, &tmpl,
                           as->session_master_key, sizeof(ret->session->master_key)))
        goto err;
    ret->session->master_key_length = tmpl;

    if (as->session_session_id != NULL) {
        if (!ssl_akamai_memcpy(ret->session->session_id, &tmpl,
                               as->session_session_id, sizeof(ret->session->session_id)))
            goto err;
        ret->session->session_id_length = tmpl;
    }

    if (!ssl_akamai_memdup((unsigned char**)&ret->s3->alpn_selected, &tmpl, as->s3_alpn_selected))
        goto err;
    if (ret->s3->alpn_selected != NULL)
        ret->s3->alpn_selected_len = tmpl;

    /* We will never be the first record */
    ret->rlayer.is_first_record = 0;

    /* RECREATE THE KEYS */
    if (!ret->method->ssl3_enc->setup_key_block(ret))
        goto err;

    if (ret->server) {
        rd_flags = SSL3_CHANGE_CIPHER_SERVER_READ;
        wr_flags = SSL3_CHANGE_CIPHER_SERVER_WRITE;
    } else {
        rd_flags = SSL3_CHANGE_CIPHER_CLIENT_READ;
        wr_flags = SSL3_CHANGE_CIPHER_CLIENT_WRITE;
    }

    if (ret->version == TLS1_3_VERSION) {
        if (!tls13_deserialize_cipher_state(ret, rd_flags))
            goto err;
        if (!tls13_deserialize_cipher_state(ret, wr_flags))
            goto err;
    } else {
        if (!ret->method->ssl3_enc->change_cipher_state(ret, rd_flags))
            goto err;
        if (!ret->method->ssl3_enc->change_cipher_state(ret, wr_flags))
            goto err;
    }
    /* Required to allow renegotiation */
    ssl3_cleanup_key_block(ret);

    /* the cipher_state functions above reset the sequence numbers and IVs */

    if (!ssl_akamai_memcpy(ret->rlayer.read_sequence, NULL,
                           as->rlayer_read_sequence, sizeof(ret->rlayer.read_sequence)))
        goto err;

    if (!ssl_akamai_memcpy(ret->rlayer.write_sequence, NULL,
                           as->rlayer_write_sequence, sizeof(ret->rlayer.write_sequence)))
        goto err;

    /* IVs only required for TLS1 and SSL3 */
    if (!ssl_akamai_memcpy(EVP_CIPHER_CTX_iv_noconst(ret->enc_read_ctx), NULL,
                           as->enc_read_ctx_iv, EVP_CIPHER_CTX_iv_length(ret->enc_read_ctx)))
        goto err;

    if (!ssl_akamai_memcpy(EVP_CIPHER_CTX_iv_noconst(ret->enc_write_ctx), NULL,
                           as->enc_write_ctx_iv, EVP_CIPHER_CTX_iv_length(ret->enc_write_ctx)))
        goto err;

    if (!ssl_akamai_memcpy(ret->s3->tmp.peer_finish_md, &tmpl,
                           as->s3_tmp_peer_finish_md, sizeof(ret->s3->tmp.peer_finish_md)))
        goto err;
    ret->s3->tmp.peer_finish_md_len = tmpl;

    if (!ssl_akamai_memcpy(ret->s3->tmp.finish_md, &tmpl,
                           as->s3_tmp_finish_md, sizeof(ret->s3->tmp.finish_md)))
        goto err;
    ret->s3->tmp.finish_md_len = tmpl;

    if ((ex_data = SSL_get_ex_data_akamai(ret)) == NULL)
        goto err;
    ex_data->options = as->ex_data_options;
    if (!ssl_akamai_memcpy(ex_data->server_random, NULL,
                           as->ex_data_server_random, sizeof(ex_data->server_random)))
        goto err;

    if (!ssl_akamai_memdup((unsigned char**)&ret->session->ext.tick,
                           &tmpl, as->session_ext_tick))
        goto err;
    if (ret->session->ext.tick != NULL)
        ret->session->ext.ticklen = tmpl;

    if (!ssl_akamai_memdup((unsigned char**)&ret->session->ticket_appdata,
                           &tmpl, as->session_ticket_appdata))
        goto err;
    if (ret->session->ticket_appdata != NULL)
        ret->session->ticket_appdata_len = tmpl;

    M_ASN1_free_of(as, SSL_AKAMAI_ASN1);
    if (a != NULL && *a == NULL)
        *a = ret;
    *pp = p;
    EVP_PKEY_free(pkey);
    return ret;

 err:
    M_ASN1_free_of(as, SSL_AKAMAI_ASN1);
    if (a == NULL || *a != ret)
        SSL_free(ret);
    EVP_PKEY_free(pkey);
    return NULL;
}
