/**
 * Verifies an ECDSA-signed JWT.
 * @param key An object representing the JWK-formatted public key that will be
 *   used to verify the ECDA-signed JWT
 * @param token The ECDSA-signed JWT to be verified
 */
export declare function verifyEcdsaJwt(key: object, token: string);
