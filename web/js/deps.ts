// All the third-party code the page runs, in one place. The site serves its
// own modules as tsc writes them, with no bundler; this one module is the
// exception, bundled with what it imports (see //:deps_bundle), so that the
// rest can import "./deps.js" like any other.
//
// - jose (https://github.com/panva/jose) reads PEM public keys into WebCrypto.
// - @noble/curves (https://github.com/paulmillr/noble-curves) parses ASN.1 DER
//   ECDSA signatures.
//
// Verification itself stays with the browser's WebCrypto.

export { importSPKI } from "jose";
export { DER } from "@noble/curves/abstract/der.js";
export { numberToBytesBE } from "@noble/curves/utils.js";
