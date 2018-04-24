#ifndef HEADER_AKABSSL_H
#define HEADER_AKABSSL_H

#include <openssl/rsa.h>
#include <openssl/x509.h>

/* FAKE OUT */
#define OPENSSL_IS_BORINGSSL

#if defined(__cplusplus)

extern "C++" {

#include <memory>

namespace bssl {

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void>
struct DeleterImpl {};

template <typename T>
struct Deleter {
  void operator()(T *ptr) {
    // Rather than specialize Deleter for each type, we specialize
    // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
    // including base.h as long as the destructor is not emitted. This matches
    // std::unique_ptr's behavior on forward-declared types.
    //
    // DeleterImpl itself is specialized in the corresponding module's header
    // and must be included to release an object. If not included, the compiler
    // will error that DeleterImpl<T> does not have a method Free.
    DeleterImpl<T>::Free(ptr);
  }
};

template <typename T, typename CleanupRet, void (*init)(T *),
          CleanupRet (*cleanup)(T *)>
class StackAllocated {
 public:
  StackAllocated() { init(&ctx_); }
  ~StackAllocated() { cleanup(&ctx_); }

  StackAllocated(const StackAllocated<T, CleanupRet, init, cleanup> &) = delete;
  T& operator=(const StackAllocated<T, CleanupRet, init, cleanup> &) = delete;

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  T *operator->() { return &ctx_; }
  const T *operator->() const { return &ctx_; }

  void Reset() {
    cleanup(&ctx_);
    init(&ctx_);
  }

 private:
  T ctx_;
};

}  // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)     \
  namespace internal {                            \
  template <>                                     \
  struct DeleterImpl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
  }

// Holds ownership of heap-allocated BoringSSL structures. Sample usage:
//   bssl::UniquePtr<RSA> rsa(RSA_new());
//   bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, internal::Deleter<T>>;

BORINGSSL_MAKE_DELETER(RSA, RSA_free)
BORINGSSL_MAKE_DELETER(SSL, SSL_free)
BORINGSSL_MAKE_DELETER(SSL_CTX, SSL_CTX_free)
BORINGSSL_MAKE_DELETER(X509, X509_free)
BORINGSSL_MAKE_DELETER(BIO, BIO_free)
BORINGSSL_MAKE_DELETER(X509_NAME, X509_NAME_free)
BORINGSSL_MAKE_DELETER(X509_INFO, X509_INFO_free)
BORINGSSL_MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)
BORINGSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)

} // namespace bssl
} // extern C++

extern "C" {

// ssl_select_cert_result_t enumerates the possible results from selecting a
// certificate with |select_certificate_cb|.
enum ssl_select_cert_result_t {
  // ssl_select_cert_success indicates that the certificate selection was
  // successful.
  ssl_select_cert_success = 1,
  // ssl_select_cert_retry indicates that the operation could not be
  // immediately completed and must be reattempted at a later point.
  ssl_select_cert_retry = 0,
  // ssl_select_cert_error indicates that a fatal error occured and the
  // handshake should be terminated.
  ssl_select_cert_error = -1,
};


static inline int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str)
{
    return SSL_CTX_set_cipher_list(ctx, str);
}

static inline int SSL_set_strict_cipher_list(SSL *ssl, const char *str)
{
    return SSL_set_cipher_list(ssl, str);
}

} // extern C
#endif

#endif
