import { verifyEcdsaJwt } from "./src";

const token =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNjAwNzM1MjYyfQ.pj_2d2ZROrGMFtJyw0GMbWJAZkRvwGQrzvUkqRe2uzBtAnHW5yiqUCVi4FNveMNL6lrAVKWX7Ri5VHUQr-zG5A";

const jwkKey = {
  use: "sig",
  kty: "EC",
  crv: "P-256",
  alg: "ES256",
  x: "SkYaM7UZDy5B9QuzBEEGs1HV8PfTlhp52kWm6L6G-3M",
  y: "j3BTz6eDQoELPKDmYafXd_zHFedC0xxmNx3kmU6_COo",
  ext: true,
};

verifyEcdsaJwt(jwkKey, token).then(console.log, console.error);
