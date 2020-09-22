# ECDSA JWT Verifier

The only purpose that this library serves is that it verifies ECDSA JWT. That's it. That's all there is to it.

The reason why this library even exists is that we need to convert the signature from base64 to Uint8Array, but, JavaScript's atob is not capable of using
