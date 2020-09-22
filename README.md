# ECDSA JWT Verifier

The only purpose that this library serves is that it verifies ECDSA JWT. That's it. That's all there is to it.

The reason why this library even exists is that we need to convert the signature from base64 to Uint8Array. JavaScript's atob is not good enough. Arbitrary binary data that are encoded in base64 translates very poorly into JavaScript's UTF-8-encoded strings.

Therefore, we're using a library called `rfc4648`, which will do the appropriate translation from base64 to Uint8Array.
