/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSLERR_H
# define HEADER_SSLERR_H

# ifdef  __cplusplus
extern "C" {
# endif
int ERR_load_SSL_strings(void);
# ifdef  __cplusplus
}
# endif

/*
 * SSL function codes.
 */
# define SSL_F_ADD_CLIENT_KEY_SHARE_EXT                   438
# define SSL_F_ADD_KEY_SHARE                              512
# define SSL_F_BYTES_TO_CIPHER_LIST                       519
# define SSL_F_CHECK_SUITEB_CIPHER_LIST                   331
# define SSL_F_CREATE_SYNTHETIC_MESSAGE_HASH              539
# define SSL_F_CT_MOVE_SCTS                               345
# define SSL_F_CT_STRICT                                  349
# define SSL_F_D2I_SSL_SESSION                            103
# define SSL_F_DANE_CTX_ENABLE                            347
# define SSL_F_DANE_MTYPE_SET                             393
# define SSL_F_DANE_TLSA_ADD                              394
# define SSL_F_DERIVE_SECRET_KEY_AND_IV                   514
# define SSL_F_DO_DTLS1_WRITE                             245
# define SSL_F_DO_SSL3_WRITE                              104
# define SSL_F_DTLS1_BUFFER_RECORD                        247
# define SSL_F_DTLS1_CHECK_TIMEOUT_NUM                    318
# define SSL_F_DTLS1_HEARTBEAT                            305
# define SSL_F_DTLS1_PREPROCESS_FRAGMENT                  288
# define SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS             424
# define SSL_F_DTLS1_PROCESS_RECORD                       257
# define SSL_F_DTLS1_READ_BYTES                           258
# define SSL_F_DTLS1_READ_FAILED                          339
# define SSL_F_DTLS1_RETRANSMIT_MESSAGE                   390
# define SSL_F_DTLS1_WRITE_APP_DATA_BYTES                 268
# define SSL_F_DTLS1_WRITE_BYTES                          545
# define SSL_F_DTLSV1_LISTEN                              350
# define SSL_F_DTLS_CONSTRUCT_CHANGE_CIPHER_SPEC          371
# define SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST        385
# define SSL_F_DTLS_GET_REASSEMBLED_MESSAGE               370
# define SSL_F_DTLS_PROCESS_HELLO_VERIFY                  386
# define SSL_F_EARLY_DATA_COUNT_OK                        532
# define SSL_F_FINAL_EC_PT_FORMATS                        485
# define SSL_F_FINAL_EMS                                  486
# define SSL_F_FINAL_KEY_SHARE                            503
# define SSL_F_FINAL_RENEGOTIATE                          483
# define SSL_F_FINAL_SIG_ALGS                             497
# define SSL_F_NSS_KEYLOG_INT                             500
# define SSL_F_OPENSSL_INIT_SSL                           342
# define SSL_F_OSSL_STATEM_CLIENT13_READ_TRANSITION       436
# define SSL_F_OSSL_STATEM_CLIENT_CONSTRUCT_MESSAGE       430
# define SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION         417
# define SSL_F_OSSL_STATEM_SERVER13_READ_TRANSITION       437
# define SSL_F_OSSL_STATEM_SERVER_CONSTRUCT_MESSAGE       431
# define SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION         418
# define SSL_F_PARSE_CA_NAMES                             541
# define SSL_F_PROCESS_KEY_SHARE_EXT                      439
# define SSL_F_READ_STATE_MACHINE                         352
# define SSL_F_SET_CLIENT_CIPHERSUITE                     540
# define SSL_F_SSL3_CHANGE_CIPHER_STATE                   129
# define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM              130
# define SSL_F_SSL3_CTRL                                  213
# define SSL_F_SSL3_CTX_CTRL                              133
# define SSL_F_SSL3_DIGEST_CACHED_RECORDS                 293
# define SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC                 292
# define SSL_F_SSL3_FINAL_FINISH_MAC                      285
# define SSL_F_SSL3_GENERATE_KEY_BLOCK                    238
# define SSL_F_SSL3_GENERATE_MASTER_SECRET                388
# define SSL_F_SSL3_GET_RECORD                            143
# define SSL_F_SSL3_INIT_FINISHED_MAC                     397
# define SSL_F_SSL3_OUTPUT_CERT_CHAIN                     147
# define SSL_F_SSL3_READ_BYTES                            148
# define SSL_F_SSL3_READ_N                                149
# define SSL_F_SSL3_SETUP_KEY_BLOCK                       157
# define SSL_F_SSL3_SETUP_READ_BUFFER                     156
# define SSL_F_SSL3_SETUP_WRITE_BUFFER                    291
# define SSL_F_SSL3_WRITE_BYTES                           158
# define SSL_F_SSL3_WRITE_PENDING                         159
# define SSL_F_SSL_ADD_CERT_CHAIN                         316
# define SSL_F_SSL_ADD_CERT_TO_BUF                        319
# define SSL_F_SSL_ADD_CERT_TO_WPACKET                    493
# define SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT        298
# define SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT                 277
# define SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT           307
# define SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK         215
# define SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK        216
# define SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT        299
# define SSL_F_SSL_ADD_SERVERHELLO_TLSEXT                 278
# define SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT           308
# define SSL_F_SSL_BAD_METHOD                             160
# define SSL_F_SSL_BUILD_CERT_CHAIN                       332
# define SSL_F_SSL_BYTES_TO_CIPHER_LIST                   161
# define SSL_F_SSL_CACHE_CIPHERLIST                       520
# define SSL_F_SSL_CERT_ADD0_CHAIN_CERT                   346
# define SSL_F_SSL_CERT_DUP                               221
# define SSL_F_SSL_CERT_NEW                               162
# define SSL_F_SSL_CERT_SET0_CHAIN                        340
# define SSL_F_SSL_CHECK_PRIVATE_KEY                      163
# define SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT               280
# define SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG            279
# define SSL_F_SSL_CIPHER_LIST_TO_BYTES                   425
# define SSL_F_SSL_CIPHER_PROCESS_RULESTR                 230
# define SSL_F_SSL_CIPHER_STRENGTH_SORT                   231
# define SSL_F_SSL_CLEAR                                  164
# define SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD            165
# define SSL_F_SSL_CONF_CMD                               334
# define SSL_F_SSL_CREATE_CIPHER_LIST                     166
# define SSL_F_SSL_CTRL                                   232
# define SSL_F_SSL_CTX_CHECK_PRIVATE_KEY                  168
# define SSL_F_SSL_CTX_ENABLE_CT                          398
# define SSL_F_SSL_CTX_MAKE_PROFILES                      309
# define SSL_F_SSL_CTX_NEW                                169
# define SSL_F_SSL_CTX_SET_ALPN_PROTOS                    343
# define SSL_F_SSL_CTX_SET_CIPHER_LIST                    269
# define SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE             290
# define SSL_F_SSL_CTX_SET_CLIENT_SESSION_CACHE           547
# define SSL_F_SSL_CTX_SET_CT_VALIDATION_CALLBACK         396
# define SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT             219
# define SSL_F_SSL_CTX_SET_SSL_VERSION                    170
# define SSL_F_SSL_CTX_USE_CERTIFICATE                    171
# define SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1               172
# define SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_BIO          548
# define SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM          549
# define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE               173
# define SSL_F_SSL_CTX_USE_CERT_AND_KEY                   4092
# define SSL_F_SSL_CTX_USE_PRIVATEKEY                     174
# define SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1                175
# define SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE                176
# define SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT              272
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY                  177
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1             178
# define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE             179
# define SSL_F_SSL_CTX_USE_SERVERINFO                     336
# define SSL_F_SSL_CTX_USE_SERVERINFO_EX                  543
# define SSL_F_SSL_CTX_USE_SERVERINFO_FILE                337
# define SSL_F_SSL_DANE_DUP                               403
# define SSL_F_SSL_DANE_ENABLE                            395
# define SSL_F_SSL_DO_CONFIG                              391
# define SSL_F_SSL_DO_HANDSHAKE                           180
# define SSL_F_SSL_DUP_CA_LIST                            408
# define SSL_F_SSL_ENABLE_CT                              402
# define SSL_F_SSL_GENERATE_SESSION_ID                    554
# define SSL_F_SSL_GET_NEW_SESSION                        181
# define SSL_F_SSL_GET_PREV_SESSION                       217
# define SSL_F_SSL_GET_SERVER_CERT_INDEX                  322
# define SSL_F_SSL_GET_SIGN_PKEY                          183
# define SSL_F_SSL_INIT_WBIO_BUFFER                       184
# define SSL_F_SSL_KEY_UPDATE                             515
# define SSL_F_SSL_LOAD_CLIENT_CA_FILE                    185
# define SSL_F_SSL_LOG_MASTER_SECRET                      498
# define SSL_F_SSL_LOG_RSA_CLIENT_KEY_EXCHANGE            499
# define SSL_F_SSL_MODULE_INIT                            392
# define SSL_F_SSL_NEW                                    186
# define SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT      300
# define SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT               302
# define SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT         310
# define SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT      301
# define SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT               303
# define SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT         311
# define SSL_F_SSL_PEEK                                   270
# define SSL_F_SSL_PEEK_EX                                432
# define SSL_F_SSL_PEEK_INTERNAL                          522
# define SSL_F_SSL_READ                                   223
# define SSL_F_SSL_READV                                  4090
# define SSL_F_SSL_READ_EARLY_DATA                        529
# define SSL_F_SSL_READ_EX                                434
# define SSL_F_SSL_READ_INTERNAL                          523
# define SSL_F_SSL_RENEGOTIATE                            516
# define SSL_F_SSL_RENEGOTIATE_ABBREVIATED                546
# define SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT                320
# define SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT                321
# define SSL_F_SSL_SESSION_DUP                            348
# define SSL_F_SSL_SESSION_NEW                            189
# define SSL_F_SSL_SESSION_PRINT_FP                       190
# define SSL_F_SSL_SESSION_SET1_ID                        423
# define SSL_F_SSL_SESSION_SET1_ID_CONTEXT                312
# define SSL_F_SSL_SET_ALPN_PROTOS                        344
# define SSL_F_SSL_SET_CERT                               191
# define SSL_F_SSL_SET_CIPHER_LIST                        271
# define SSL_F_SSL_SET_CT_VALIDATION_CALLBACK             399
# define SSL_F_SSL_SET_FD                                 192
# define SSL_F_SSL_SET_PKEY                               193
# define SSL_F_SSL_SET_RFD                                194
# define SSL_F_SSL_SET_SESSION                            195
# define SSL_F_SSL_SET_SESSION_ID_CONTEXT                 218
# define SSL_F_SSL_SET_SESSION_TICKET_EXT                 294
# define SSL_F_SSL_SET_WFD                                196
# define SSL_F_SSL_SHUTDOWN                               224
# define SSL_F_SSL_SRP_CTX_INIT                           313
# define SSL_F_SSL_START_ASYNC_JOB                        389
# define SSL_F_SSL_UNDEFINED_FUNCTION                     197
# define SSL_F_SSL_UNDEFINED_VOID_FUNCTION                244
# define SSL_F_SSL_USE_CERTIFICATE                        198
# define SSL_F_SSL_USE_CERTIFICATE_ASN1                   199
# define SSL_F_SSL_USE_CERTIFICATE_FILE                   200
# define SSL_F_SSL_USE_CERT_AND_KEY                       4091
# define SSL_F_SSL_USE_PRIVATEKEY                         201
# define SSL_F_SSL_USE_PRIVATEKEY_ASN1                    202
# define SSL_F_SSL_USE_PRIVATEKEY_FILE                    203
# define SSL_F_SSL_USE_PSK_IDENTITY_HINT                  273
# define SSL_F_SSL_USE_RSAPRIVATEKEY                      204
# define SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1                 205
# define SSL_F_SSL_USE_RSAPRIVATEKEY_FILE                 206
# define SSL_F_SSL_VALIDATE_CT                            400
# define SSL_F_SSL_VERIFY_CERT_CHAIN                      207
# define SSL_F_SSL_WRITE                                  208
# define SSL_F_SSL_WRITEV                                 4089
# define SSL_F_SSL_WRITE_EARLY_DATA                       526
# define SSL_F_SSL_WRITE_EARLY_FINISH                     527
# define SSL_F_SSL_WRITE_EX                               433
# define SSL_F_SSL_WRITE_INTERNAL                         524
# define SSL_F_STATE_MACHINE                              353
# define SSL_F_TLS12_CHECK_PEER_SIGALG                    333
# define SSL_F_TLS12_COPY_SIGALGS                         533
# define SSL_F_TLS13_CHANGE_CIPHER_STATE                  440
# define SSL_F_TLS13_SETUP_KEY_BLOCK                      441
# define SSL_F_TLS1_CHANGE_CIPHER_STATE                   209
# define SSL_F_TLS1_CHECK_DUPLICATE_EXTENSIONS            341
# define SSL_F_TLS1_ENC                                   401
# define SSL_F_TLS1_EXPORT_KEYING_MATERIAL                314
# define SSL_F_TLS1_GET_CURVELIST                         338
# define SSL_F_TLS1_PRF                                   284
# define SSL_F_TLS1_SETUP_KEY_BLOCK                       211
# define SSL_F_TLS1_SET_SERVER_SIGALGS                    335
# define SSL_F_TLS_CHOOSE_SIGALG                          513
# define SSL_F_TLS_CLIENT_KEY_EXCHANGE_POST_WORK          354
# define SSL_F_TLS_COLLECT_EXTENSIONS                     435
# define SSL_F_TLS_CONSTRUCT_CERTIFICATE_AUTHORITIES      542
# define SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST          372
# define SSL_F_TLS_CONSTRUCT_CERT_STATUS                  429
# define SSL_F_TLS_CONSTRUCT_CERT_STATUS_BODY             494
# define SSL_F_TLS_CONSTRUCT_CERT_VERIFY                  496
# define SSL_F_TLS_CONSTRUCT_CHANGE_CIPHER_SPEC           427
# define SSL_F_TLS_CONSTRUCT_CKE_DHE                      404
# define SSL_F_TLS_CONSTRUCT_CKE_ECDHE                    405
# define SSL_F_TLS_CONSTRUCT_CKE_GOST                     406
# define SSL_F_TLS_CONSTRUCT_CKE_PSK_PREAMBLE             407
# define SSL_F_TLS_CONSTRUCT_CKE_RSA                      409
# define SSL_F_TLS_CONSTRUCT_CKE_SRP                      410
# define SSL_F_TLS_CONSTRUCT_CLIENT_CERTIFICATE           484
# define SSL_F_TLS_CONSTRUCT_CLIENT_HELLO                 487
# define SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE          488
# define SSL_F_TLS_CONSTRUCT_CLIENT_VERIFY                489
# define SSL_F_TLS_CONSTRUCT_CTOS_ALPN                    466
# define SSL_F_TLS_CONSTRUCT_CTOS_CERTIFICATE             355
# define SSL_F_TLS_CONSTRUCT_CTOS_COOKIE                  535
# define SSL_F_TLS_CONSTRUCT_CTOS_EARLY_DATA              530
# define SSL_F_TLS_CONSTRUCT_CTOS_EC_PT_FORMATS           467
# define SSL_F_TLS_CONSTRUCT_CTOS_EMS                     468
# define SSL_F_TLS_CONSTRUCT_CTOS_ETM                     469
# define SSL_F_TLS_CONSTRUCT_CTOS_HELLO                   356
# define SSL_F_TLS_CONSTRUCT_CTOS_KEY_EXCHANGE            357
# define SSL_F_TLS_CONSTRUCT_CTOS_KEY_SHARE               470
# define SSL_F_TLS_CONSTRUCT_CTOS_NPN                     471
# define SSL_F_TLS_CONSTRUCT_CTOS_PADDING                 472
# define SSL_F_TLS_CONSTRUCT_CTOS_PSK                     501
# define SSL_F_TLS_CONSTRUCT_CTOS_PSK_KEX_MODES           509
# define SSL_F_TLS_CONSTRUCT_CTOS_RENEGOTIATE             473
# define SSL_F_TLS_CONSTRUCT_CTOS_SCT                     474
# define SSL_F_TLS_CONSTRUCT_CTOS_SERVER_NAME             475
# define SSL_F_TLS_CONSTRUCT_CTOS_SESSION_TICKET          476
# define SSL_F_TLS_CONSTRUCT_CTOS_SIG_ALGS                477
# define SSL_F_TLS_CONSTRUCT_CTOS_SRP                     478
# define SSL_F_TLS_CONSTRUCT_CTOS_STATUS_REQUEST          479
# define SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_GROUPS        480
# define SSL_F_TLS_CONSTRUCT_CTOS_SUPPORTED_VERSIONS      481
# define SSL_F_TLS_CONSTRUCT_CTOS_USE_SRTP                482
# define SSL_F_TLS_CONSTRUCT_CTOS_VERIFY                  358
# define SSL_F_TLS_CONSTRUCT_ENCRYPTED_EXTENSIONS         443
# define SSL_F_TLS_CONSTRUCT_END_OF_EARLY_DATA            536
# define SSL_F_TLS_CONSTRUCT_EXTENSIONS                   447
# define SSL_F_TLS_CONSTRUCT_FINISHED                     359
# define SSL_F_TLS_CONSTRUCT_HELLO_REQUEST                373
# define SSL_F_TLS_CONSTRUCT_HELLO_RETRY_REQUEST          510
# define SSL_F_TLS_CONSTRUCT_KEY_UPDATE                   517
# define SSL_F_TLS_CONSTRUCT_NEW_SESSION_TICKET           428
# define SSL_F_TLS_CONSTRUCT_NEXT_PROTO                   426
# define SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE           490
# define SSL_F_TLS_CONSTRUCT_SERVER_HELLO                 491
# define SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE          492
# define SSL_F_TLS_CONSTRUCT_STOC_ALPN                    451
# define SSL_F_TLS_CONSTRUCT_STOC_CERTIFICATE             374
# define SSL_F_TLS_CONSTRUCT_STOC_CRYPTOPRO_BUG           452
# define SSL_F_TLS_CONSTRUCT_STOC_DONE                    375
# define SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA              531
# define SSL_F_TLS_CONSTRUCT_STOC_EARLY_DATA_INFO         525
# define SSL_F_TLS_CONSTRUCT_STOC_EC_PT_FORMATS           453
# define SSL_F_TLS_CONSTRUCT_STOC_EMS                     454
# define SSL_F_TLS_CONSTRUCT_STOC_ETM                     455
# define SSL_F_TLS_CONSTRUCT_STOC_HELLO                   376
# define SSL_F_TLS_CONSTRUCT_STOC_KEY_EXCHANGE            377
# define SSL_F_TLS_CONSTRUCT_STOC_KEY_SHARE               456
# define SSL_F_TLS_CONSTRUCT_STOC_NEXT_PROTO_NEG          457
# define SSL_F_TLS_CONSTRUCT_STOC_PSK                     504
# define SSL_F_TLS_CONSTRUCT_STOC_RENEGOTIATE             458
# define SSL_F_TLS_CONSTRUCT_STOC_SERVER_NAME             459
# define SSL_F_TLS_CONSTRUCT_STOC_SESSION_TICKET          460
# define SSL_F_TLS_CONSTRUCT_STOC_STATUS_REQUEST          461
# define SSL_F_TLS_CONSTRUCT_STOC_SUPPORTED_GROUPS        544
# define SSL_F_TLS_CONSTRUCT_STOC_USE_SRTP                462
# define SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO        521
# define SSL_F_TLS_GET_MESSAGE_BODY                       351
# define SSL_F_TLS_GET_MESSAGE_HEADER                     387
# define SSL_F_TLS_PARSE_CLIENTHELLO_TLSEXT               449
# define SSL_F_TLS_PARSE_CTOS_KEY_SHARE                   463
# define SSL_F_TLS_PARSE_CTOS_PSK                         505
# define SSL_F_TLS_PARSE_CTOS_RENEGOTIATE                 464
# define SSL_F_TLS_PARSE_CTOS_USE_SRTP                    465
# define SSL_F_TLS_PARSE_STOC_COOKIE                      534
# define SSL_F_TLS_PARSE_STOC_EARLY_DATA                  538
# define SSL_F_TLS_PARSE_STOC_EARLY_DATA_INFO             528
# define SSL_F_TLS_PARSE_STOC_KEY_SHARE                   445
# define SSL_F_TLS_PARSE_STOC_PSK                         502
# define SSL_F_TLS_PARSE_STOC_RENEGOTIATE                 448
# define SSL_F_TLS_PARSE_STOC_USE_SRTP                    446
# define SSL_F_TLS_POST_PROCESS_CLIENT_HELLO              378
# define SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE       384
# define SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE             360
# define SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST            361
# define SSL_F_TLS_PROCESS_CERT_STATUS                    362
# define SSL_F_TLS_PROCESS_CERT_STATUS_BODY               495
# define SSL_F_TLS_PROCESS_CERT_VERIFY                    379
# define SSL_F_TLS_PROCESS_CHANGE_CIPHER_SPEC             363
# define SSL_F_TLS_PROCESS_CKE_DHE                        411
# define SSL_F_TLS_PROCESS_CKE_ECDHE                      412
# define SSL_F_TLS_PROCESS_CKE_GOST                       413
# define SSL_F_TLS_PROCESS_CKE_PSK_PREAMBLE               414
# define SSL_F_TLS_PROCESS_CKE_RSA                        415
# define SSL_F_TLS_PROCESS_CKE_SRP                        416
# define SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE             380
# define SSL_F_TLS_PROCESS_CLIENT_HELLO                   381
# define SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE            382
# define SSL_F_TLS_PROCESS_ENCRYPTED_EXTENSIONS           444
# define SSL_F_TLS_PROCESS_END_OF_EARLY_DATA              537
# define SSL_F_TLS_PROCESS_FINISHED                       364
# define SSL_F_TLS_PROCESS_HELLO_REQ                      507
# define SSL_F_TLS_PROCESS_HELLO_RETRY_REQUEST            511
# define SSL_F_TLS_PROCESS_INITIAL_SERVER_FLIGHT          442
# define SSL_F_TLS_PROCESS_KEY_EXCHANGE                   365
# define SSL_F_TLS_PROCESS_KEY_UPDATE                     518
# define SSL_F_TLS_PROCESS_NEW_SESSION_TICKET             366
# define SSL_F_TLS_PROCESS_NEXT_PROTO                     383
# define SSL_F_TLS_PROCESS_SERVER_CERTIFICATE             367
# define SSL_F_TLS_PROCESS_SERVER_DONE                    368
# define SSL_F_TLS_PROCESS_SERVER_HELLO                   369
# define SSL_F_TLS_PROCESS_SKE_DHE                        419
# define SSL_F_TLS_PROCESS_SKE_ECDHE                      420
# define SSL_F_TLS_PROCESS_SKE_PSK_PREAMBLE               421
# define SSL_F_TLS_PROCESS_SKE_SRP                        422
# define SSL_F_TLS_PSK_DO_BINDER                          506
# define SSL_F_TLS_SCAN_CLIENTHELLO_TLSEXT                450
# define SSL_F_TLS_SETUP_HANDSHAKE                        508
# define SSL_F_USE_CERTIFICATE_CHAIN_FILE                 220

/*
 * SSL reason codes.
 */
# define SSL_R_APP_DATA_IN_HANDSHAKE                      100
# define SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 272
# define SSL_R_AT_LEAST_TLS_1_0_NEEDED_IN_FIPS_MODE       143
# define SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE     158
# define SSL_R_BAD_CHANGE_CIPHER_SPEC                     103
# define SSL_R_BAD_CIPHER                                 186
# define SSL_R_BAD_DATA                                   390
# define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK              106
# define SSL_R_BAD_DECOMPRESSION                          107
# define SSL_R_BAD_DH_VALUE                               102
# define SSL_R_BAD_DIGEST_LENGTH                          111
# define SSL_R_BAD_ECC_CERT                               304
# define SSL_R_BAD_ECPOINT                                306
# define SSL_R_BAD_EXTENSION                              110
# define SSL_R_BAD_HANDSHAKE_LENGTH                       332
# define SSL_R_BAD_HELLO_REQUEST                          105
# define SSL_R_BAD_KEY_SHARE                              108
# define SSL_R_BAD_KEY_UPDATE                             122
# define SSL_R_BAD_LENGTH                                 271
# define SSL_R_BAD_PACKET_LENGTH                          115
# define SSL_R_BAD_PROTOCOL_VERSION_NUMBER                116
# define SSL_R_BAD_PSK                                    219
# define SSL_R_BAD_PSK_IDENTITY                           114
# define SSL_R_BAD_RECORD_TYPE                            443
# define SSL_R_BAD_RSA_ENCRYPT                            119
# define SSL_R_BAD_SIGNATURE                              123
# define SSL_R_BAD_SRP_A_LENGTH                           347
# define SSL_R_BAD_SRP_PARAMETERS                         371
# define SSL_R_BAD_SRTP_MKI_VALUE                         352
# define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST           353
# define SSL_R_BAD_SSL_FILETYPE                           124
# define SSL_R_BAD_VALUE                                  384
# define SSL_R_BAD_WRITE_RETRY                            127
# define SSL_R_BIO_NOT_SET                                128
# define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  129
# define SSL_R_BN_LIB                                     130
# define SSL_R_CANNOT_CHANGE_CIPHER                       109
# define SSL_R_CA_DN_LENGTH_MISMATCH                      131
# define SSL_R_CA_KEY_TOO_SMALL                           397
# define SSL_R_CA_MD_TOO_WEAK                             398
# define SSL_R_CCS_RECEIVED_EARLY                         133
# define SSL_R_CERTIFICATE_VERIFY_FAILED                  134
# define SSL_R_CERT_CB_ERROR                              377
# define SSL_R_CERT_LENGTH_MISMATCH                       135
# define SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED             218
# define SSL_R_CIPHER_CODE_WRONG_LENGTH                   137
# define SSL_R_CIPHER_OR_HASH_UNAVAILABLE                 138
# define SSL_R_CLIENTHELLO_TLSEXT                         226
# define SSL_R_COMPRESSED_LENGTH_TOO_LONG                 140
# define SSL_R_COMPRESSION_DISABLED                       343
# define SSL_R_COMPRESSION_FAILURE                        141
# define SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE    307
# define SSL_R_COMPRESSION_LIBRARY_ERROR                  142
# define SSL_R_CONNECTION_TYPE_NOT_SET                    144
# define SSL_R_CONTEXT_NOT_DANE_ENABLED                   167
# define SSL_R_COOKIE_GEN_CALLBACK_FAILURE                400
# define SSL_R_COOKIE_MISMATCH                            308
# define SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED       206
# define SSL_R_DANE_ALREADY_ENABLED                       172
# define SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL            173
# define SSL_R_DANE_NOT_ENABLED                           175
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE                  180
# define SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE            184
# define SSL_R_DANE_TLSA_BAD_DATA_LENGTH                  189
# define SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH                192
# define SSL_R_DANE_TLSA_BAD_MATCHING_TYPE                200
# define SSL_R_DANE_TLSA_BAD_PUBLIC_KEY                   201
# define SSL_R_DANE_TLSA_BAD_SELECTOR                     202
# define SSL_R_DANE_TLSA_NULL_DATA                        203
# define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              145
# define SSL_R_DATA_LENGTH_TOO_LONG                       146
# define SSL_R_DECRYPTION_FAILED                          147
# define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        281
# define SSL_R_DH_KEY_TOO_SMALL                           394
# define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG            148
# define SSL_R_DIGEST_CHECK_FAILED                        149
# define SSL_R_DTLS_MESSAGE_TOO_BIG                       334
# define SSL_R_DUPLICATE_COMPRESSION_ID                   309
# define SSL_R_ECC_CERT_NOT_FOR_SIGNING                   318
# define SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE              374
# define SSL_R_EE_KEY_TOO_SMALL                           399
# define SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST         354
# define SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  150
# define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              151
# define SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN             204
# define SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE                  194
# define SSL_R_EXCESSIVE_MESSAGE_SIZE                     152
# define SSL_R_EXTRA_DATA_IN_MESSAGE                      153
# define SSL_R_EXT_LENGTH_MISMATCH                        163
# define SSL_R_FAILED_TO_INIT_ASYNC                       405
# define SSL_R_FRAGMENTED_CLIENT_HELLO                    401
# define SSL_R_GOT_A_FIN_BEFORE_A_CCS                     154
# define SSL_R_HTTPS_PROXY_REQUEST                        155
# define SSL_R_HTTP_REQUEST                               156
# define SSL_R_ILLEGAL_POINT_COMPRESSION                  162
# define SSL_R_ILLEGAL_SUITEB_DIGEST                      380
# define SSL_R_INAPPROPRIATE_FALLBACK                     373
# define SSL_R_INCONSISTENT_COMPRESSION                   340
# define SSL_R_INCONSISTENT_EARLY_DATA_ALPN               222
# define SSL_R_INCONSISTENT_EARLY_DATA_SNI                231
# define SSL_R_INCONSISTENT_EXTMS                         104
# define SSL_R_INVALID_ALERT                              205
# define SSL_R_INVALID_COMMAND                            280
# define SSL_R_INVALID_COMPRESSION_ALGORITHM              341
# define SSL_R_INVALID_CONFIGURATION_NAME                 113
# define SSL_R_INVALID_CT_VALIDATION_TYPE                 212
# define SSL_R_INVALID_KEY_UPDATE_TYPE                    120
# define SSL_R_INVALID_MAX_EARLY_DATA                     174
# define SSL_R_INVALID_NULL_CMD_NAME                      385
# define SSL_R_INVALID_SEQUENCE_NUMBER                    402
# define SSL_R_INVALID_SERVERINFO_DATA                    388
# define SSL_R_INVALID_SRP_USERNAME                       357
# define SSL_R_INVALID_STATUS_RESPONSE                    328
# define SSL_R_INVALID_TICKET_KEYS_LENGTH                 325
# define SSL_R_LENGTH_MISMATCH                            159
# define SSL_R_LENGTH_TOO_LONG                            404
# define SSL_R_LENGTH_TOO_SHORT                           160
# define SSL_R_LIBRARY_BUG                                274
# define SSL_R_LIBRARY_HAS_NO_CIPHERS                     161
# define SSL_R_MISSING_DSA_SIGNING_CERT                   165
# define SSL_R_MISSING_ECDSA_SIGNING_CERT                 381
# define SSL_R_MISSING_RSA_CERTIFICATE                    168
# define SSL_R_MISSING_RSA_ENCRYPTING_CERT                169
# define SSL_R_MISSING_RSA_SIGNING_CERT                   170
# define SSL_R_MISSING_SIGALGS_EXTENSION                  112
# define SSL_R_MISSING_SIGNING_CERT                       221
# define SSL_R_MISSING_SRP_PARAM                          358
# define SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION         209
# define SSL_R_MISSING_TMP_DH_KEY                         171
# define SSL_R_MISSING_TMP_ECDH_KEY                       311
# define SSL_R_NOT_ON_RECORD_BOUNDARY                     182
# define SSL_R_NO_CERTIFICATES_RETURNED                   176
# define SSL_R_NO_CERTIFICATE_ASSIGNED                    177
# define SSL_R_NO_CERTIFICATE_SET                         179
# define SSL_R_NO_CHANGE_FOLLOWING_HRR                    214
# define SSL_R_NO_CIPHERS_AVAILABLE                       181
# define SSL_R_NO_CIPHERS_SPECIFIED                       183
# define SSL_R_NO_CIPHER_MATCH                            185
# define SSL_R_NO_CLIENT_CERT_METHOD                      331
# define SSL_R_NO_COMPRESSION_SPECIFIED                   187
# define SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER           330
# define SSL_R_NO_METHOD_SPECIFIED                        188
# define SSL_R_NO_PEM_EXTENSIONS                          389
# define SSL_R_NO_PRIVATE_KEY_ASSIGNED                    190
# define SSL_R_NO_PROTOCOLS_AVAILABLE                     191
# define SSL_R_NO_RENEGOTIATION                           339
# define SSL_R_NO_REQUIRED_DIGEST                         324
# define SSL_R_NO_SHARED_CIPHER                           193
# define SSL_R_NO_SHARED_GROUPS                           410
# define SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             376
# define SSL_R_NO_SRTP_PROFILES                           359
# define SSL_R_NO_SUITABLE_KEY_SHARE                      101
# define SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            118
# define SSL_R_NO_VALID_SCTS                              216
# define SSL_R_NO_VERIFY_COOKIE_CALLBACK                  403
# define SSL_R_NULL_SSL_CTX                               195
# define SSL_R_NULL_SSL_METHOD_PASSED                     196
# define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED            197
# define SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 344
# define SSL_R_PACKET_LENGTH_TOO_LONG                     198
# define SSL_R_PARSE_TLSEXT                               227
# define SSL_R_PATH_TOO_LONG                              270
# define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE          199
# define SSL_R_PEM_NAME_BAD_PREFIX                        391
# define SSL_R_PEM_NAME_TOO_SHORT                         392
# define SSL_R_PIPELINE_FAILURE                           406
# define SSL_R_PROTOCOL_IS_SHUTDOWN                       207
# define SSL_R_PSK_IDENTITY_NOT_FOUND                     223
# define SSL_R_PSK_NO_CLIENT_CB                           224
# define SSL_R_PSK_NO_SERVER_CB                           225
# define SSL_R_READV_IN_PROGRESS                          999
# define SSL_R_READ_BIO_NOT_SET                           211
# define SSL_R_READ_TIMEOUT_EXPIRED                       312
# define SSL_R_RECORD_LENGTH_MISMATCH                     213
# define SSL_R_RECORD_TOO_SMALL                           298
# define SSL_R_RENEGOTIATE_EXT_TOO_LONG                   335
# define SSL_R_RENEGOTIATION_ENCODING_ERR                 336
# define SSL_R_RENEGOTIATION_MISMATCH                     337
# define SSL_R_REQUIRED_CIPHER_MISSING                    215
# define SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING     342
# define SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           345
# define SSL_R_SCT_VERIFICATION_FAILED                    208
# define SSL_R_SERVERHELLO_TLSEXT                         275
# define SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED           277
# define SSL_R_SHUTDOWN_WHILE_IN_INIT                     407
# define SSL_R_SIGNATURE_ALGORITHMS_ERROR                 360
# define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE      220
# define SSL_R_SRP_A_CALC                                 361
# define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES           362
# define SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG      363
# define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE            364
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME                319
# define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE           320
# define SSL_R_SSL3_SESSION_ID_TOO_LONG                   300
# define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                1042
# define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 1020
# define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            1045
# define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            1044
# define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            1046
# define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          1030
# define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              1040
# define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              1047
# define SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 1041
# define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             1010
# define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        1043
# define SSL_R_SSL_COMMAND_SECTION_EMPTY                  117
# define SSL_R_SSL_COMMAND_SECTION_NOT_FOUND              125
# define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION         228
# define SSL_R_SSL_HANDSHAKE_FAILURE                      229
# define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS                 230
# define SSL_R_SSL_NEGATIVE_LENGTH                        372
# define SSL_R_SSL_SECTION_EMPTY                          126
# define SSL_R_SSL_SECTION_NOT_FOUND                      136
# define SSL_R_SSL_SESSION_ID_CALLBACK_FAILED             301
# define SSL_R_SSL_SESSION_ID_CONFLICT                    302
# define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG            273
# define SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH              303
# define SSL_R_SSL_SESSION_ID_TOO_LONG                    408
# define SSL_R_SSL_SESSION_VERSION_MISMATCH               210
# define SSL_R_STILL_IN_INIT                              121
# define SSL_R_TLSV1_ALERT_ACCESS_DENIED                  1049
# define SSL_R_TLSV1_ALERT_DECODE_ERROR                   1050
# define SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              1021
# define SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  1051
# define SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             1060
# define SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK         1086
# define SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          1071
# define SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 1080
# define SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               1100
# define SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               1070
# define SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                1022
# define SSL_R_TLSV1_ALERT_UNKNOWN_CA                     1048
# define SSL_R_TLSV1_ALERT_USER_CANCELLED                 1090
# define SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE           1114
# define SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE      1113
# define SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE             1111
# define SSL_R_TLSV1_UNRECOGNIZED_NAME                    1112
# define SSL_R_TLSV1_UNSUPPORTED_EXTENSION                1110
# define SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT           365
# define SSL_R_TLS_HEARTBEAT_PENDING                      366
# define SSL_R_TLS_ILLEGAL_EXPORTER_LABEL                 367
# define SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST             157
# define SSL_R_TOO_MANY_KEY_UPDATES                       132
# define SSL_R_TOO_MANY_WARN_ALERTS                       409
# define SSL_R_TOO_MUCH_EARLY_DATA                        164
# define SSL_R_UNABLE_TO_COPY                             998
# define SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS             314
# define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS       239
# define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES           242
# define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES          243
# define SSL_R_UNEXPECTED_END_OF_EARLY_DATA               178
# define SSL_R_UNEXPECTED_MESSAGE                         244
# define SSL_R_UNEXPECTED_RECORD                          245
# define SSL_R_UNINITIALIZED                              276
# define SSL_R_UNKNOWN_ALERT_TYPE                         246
# define SSL_R_UNKNOWN_CERTIFICATE_TYPE                   247
# define SSL_R_UNKNOWN_CIPHER_RETURNED                    248
# define SSL_R_UNKNOWN_CIPHER_TYPE                        249
# define SSL_R_UNKNOWN_CMD_NAME                           386
# define SSL_R_UNKNOWN_COMMAND                            139
# define SSL_R_UNKNOWN_DIGEST                             368
# define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE                  250
# define SSL_R_UNKNOWN_PKEY_TYPE                          251
# define SSL_R_UNKNOWN_PROTOCOL                           252
# define SSL_R_UNKNOWN_SSL_VERSION                        254
# define SSL_R_UNKNOWN_STATE                              255
# define SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       338
# define SSL_R_UNSOLICITED_EXTENSION                      217
# define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM          257
# define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE                 315
# define SSL_R_UNSUPPORTED_PROTOCOL                       258
# define SSL_R_UNSUPPORTED_SSL_VERSION                    259
# define SSL_R_UNSUPPORTED_STATUS_TYPE                    329
# define SSL_R_USE_SRTP_NOT_NEGOTIATED                    369
# define SSL_R_VERSION_TOO_HIGH                           166
# define SSL_R_VERSION_TOO_LOW                            396
# define SSL_R_WRONG_CERTIFICATE_TYPE                     383
# define SSL_R_WRONG_CIPHER_RETURNED                      261
# define SSL_R_WRONG_CURVE                                378
# define SSL_R_WRONG_SIGNATURE_LENGTH                     264
# define SSL_R_WRONG_SIGNATURE_SIZE                       265
# define SSL_R_WRONG_SIGNATURE_TYPE                       370
# define SSL_R_WRONG_SSL_VERSION                          266
# define SSL_R_WRONG_VERSION_NUMBER                       267
# define SSL_R_X509_LIB                                   268
# define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS           269

#endif
