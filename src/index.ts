import { base64url } from "rfc4648";

function parseJwt(jwt: string) {
  const [headerb64, payloadb64] = jwt.split(".");

  const header = JSON.parse(atob(headerb64));
  const payload = JSON.parse(atob(payloadb64));

  return { header, payload };
}

type Algorithms = "ES256" | "ES384" | "ES512";
type HashAlgorithms = "SHA-256" | "SHA-384" | "SHA-512";

const hashMap = new Map<Algorithms, HashAlgorithms>([
  ["ES256", "SHA-256"],
  ["ES384", "SHA-384"],
  ["ES512", "SHA-512"],
]);

function determineHash(jwt: string): string {
  const {
    header: { alg },
  } = parseJwt(jwt);
  if (!hashMap.has(alg)) {
    throw new Error("Algorithm not acceptable");
  }
  return hashMap.get(alg);
}

function cleanUpJwk({ alg, ...remainder }: any): any {
  return remainder;
}

function getJwtMessage(jwt: string): Uint8Array {
  return new TextEncoder().encode(jwt.split(".").slice(0, 2).join("."));
}

function getJwtSignature(jwt: string): Uint8Array {
  return base64url.parse(jwt.split(".")[2]);
}

/**
 * Verifies an ECDSA-signed JWT.
 * @param {object} key An object representing the JWK-formatted public key that
 *   will be used to verify the ECDA-signed JWT
 * @param {string} token The ECDSA-signed JWT to be verified
 */
export async function verifyEcdsaJwt(
  key: any,
  token: string
): Promise<boolean> {
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
