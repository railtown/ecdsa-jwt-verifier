/**
 * Verifies an ECDSA-signed JWT.
 * @param {object} key An object representing the JWK-formatted public key that
 *   will be used to verify the ECDA-signed JWT
 * @param {string} token The ECDSA-signed JWT to be verified
 */
export declare function verifyEcdsaJwt(key: any, token: string): Promise<boolean>;
