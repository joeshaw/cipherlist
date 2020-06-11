A tool which lists what TLS 1.2 and TLS 1.3 ciphersuites are supported.
This is an example tool from [this blog
post](https://www.joeshaw.org/abusing-go-linkname-to-customize-tls13-cipher-suites/).

Example usage:

```
$ go run cipherlist.go joeshaw.org

Supported TLS 1.2 ciphers
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

Supported TLS 1.3 ciphers
  TLS_AES_128_GCM_SHA256
  TLS_CHACHA20_POLY1305_SHA256
  TLS_AES_256_GCM_SHA384
```