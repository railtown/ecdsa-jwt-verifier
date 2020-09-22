import { base64url } from "rfc4648";

function parseJwt(jwt) {
  const { headerb64, payloadb64 } = jwt.split(".");

  const header = atob(headerb64);
  const payload = atob(payloadb64);

  return { header, payload };
}

const hashMap = new Map([
  ["ES256", "SHA-256"],
  ["ES384", "SHA-348"],
  ["ES512", "SHA-512"],
]);

function determineHash(jwt) {
  const {
    header: { alg },
  } = parseJwt(jwt);
  if (!hashMap.has(alg)) {
    throw new Error("Algorithm not acceptable");
  }
  return hashMap.get(alg);
}

function cleanUpJwk({ alg, ...remainder }) {
  return remainder;
}

function getJwtMessage(jwt) {
  return new TextEncoder().encode(jwt.split(".").slice(0, 2).join("."));
}

function getJwtSignature(jwt) {
  return base64url.parse(jwt.split(".")[2]);
}

/**
 * Verifies an ECDSA-signed JWT.
 * @param {object} key An object representing the JWK-formatted public key that
 *   will be used to verify the ECDA-signed JWT
 * @param {string} token The ECDSA-signed JWT to be verified
 */
export async function verifyEcdsaJwt(key, token) {
  const signature = getJwtSignature(token);
  const message = getJwtMessage(token);

  let result = await window.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: determineHash(token) },
    },
    cleanUpJwk(key),
    signature,
    message
  );

  return result;
}
