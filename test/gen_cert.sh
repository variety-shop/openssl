#!/bin/bash

OPENSSL_DIR=..
OPENSSL="$OPENSSL_DIR/apps/openssl"
OPENSSL_CONF="$OPENSSL_DIR/apps/openssl.cnf"

OUT_DIR=gen
mkdir -p "$OUT_DIR"

gen_cert() {
  local name=$1
  rm -f "$OUT_DIR/$1."*

  $OPENSSL genrsa -out $OUT_DIR/$1.key 2048  2>/dev/null &&
  chmod 400 $OUT_DIR/$name.key &&
  $OPENSSL req -new -nodes -config $OPENSSL_CONF -key $OUT_DIR/$name.key >/dev/null \
  -out $OUT_DIR/$name.csr << EOF &&
DE
.
.
.
.
$name.tests.openssl.org
.


EOF
  $OPENSSL x509 -req -days 3 -in $OUT_DIR/$name.csr \
    -signkey $OUT_DIR/$name.key -out $OUT_DIR/$name.crt &&
    echo "certificate $name generated." && return 0
  return 1
}

gen_cert "$@"

