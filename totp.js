const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_LOOKUP = new Map(
  [...BASE32_ALPHABET].map((character, index) => [character, index]),
);
const WEBCRYPTO_HASH = new Map([
  ["SHA1", "SHA-1"],
  ["SHA256", "SHA-256"],
  ["SHA512", "SHA-512"],
]);

export function base32ToBytes(secret) {
  if (typeof secret !== "string") {
    throw new TypeError("The Base32 secret must be text.");
  }

  const normalized = secret.replace(/[\s=-]/g, "").toUpperCase();
  if (!normalized) {
    throw new Error("Enter a Base32 secret.");
  }

  let buffer = 0;
  let bits = 0;
  const bytes = [];

  for (const character of normalized) {
    const value = BASE32_LOOKUP.get(character);
    if (value === undefined) {
      throw new Error("The secret contains a character that is not valid Base32.");
    }
    buffer = (buffer << 5) | value;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }

  if (bytes.length === 0) {
    throw new Error("The Base32 secret is too short.");
  }

  return new Uint8Array(bytes);
}

export function parseOtpAuthUri(rawUri) {
  let uri;
  try {
    uri = new URL(rawUri.trim());
  } catch {
    throw new Error("That is not a valid authenticator setup URI.");
  }

  if (uri.protocol !== "otpauth:" || uri.hostname.toLowerCase() !== "totp") {
    throw new Error("Only TOTP setup URIs (otpauth://totp/…) are supported.");
  }

  let label;
  try {
    label = decodeURIComponent(uri.pathname.replace(/^\/+/, ""));
  } catch {
    throw new Error("The account label in this setup URI is malformed.");
  }

  const colonIndex = label.indexOf(":");
  const labelIssuer = colonIndex >= 0 ? label.slice(0, colonIndex).trim() : "";
  const account = (colonIndex >= 0 ? label.slice(colonIndex + 1) : label).trim();
  const issuerParameter = (uri.searchParams.get("issuer") || "").trim();

  if (labelIssuer && issuerParameter && labelIssuer !== issuerParameter) {
    throw new Error("The issuer in the label does not match the issuer parameter.");
  }

  const secret = (uri.searchParams.get("secret") || "").trim();
  base32ToBytes(secret);

  const algorithm = (uri.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (!WEBCRYPTO_HASH.has(algorithm)) {
    throw new Error("The setup URI uses an unsupported hash algorithm.");
  }

  const digits = Number(uri.searchParams.get("digits") || 6);
  if (![6, 8].includes(digits)) {
    throw new Error("Only 6- and 8-digit TOTP codes are supported.");
  }

  const period = Number(uri.searchParams.get("period") || 30);
  if (!Number.isSafeInteger(period) || period < 1 || period > 86400) {
    throw new Error("The TOTP period in the setup URI is invalid.");
  }

  if (!account) {
    throw new Error("The setup URI does not contain an account name.");
  }

  return {
    issuer: issuerParameter || labelIssuer,
    account,
    secret,
    algorithm,
    digits,
    period,
  };
}

export async function generateTotp(
  { secret, period = 30, digits = 6, algorithm = "SHA1" },
  timestamp = Date.now(),
) {
  if (!Number.isSafeInteger(period) || period < 1) {
    throw new Error("The TOTP period must be a positive whole number of seconds.");
  }
  if (![6, 8].includes(digits)) {
    throw new Error("TOTP codes must contain 6 or 8 digits.");
  }

  const hash = String(algorithm).toUpperCase();
  const webCryptoHash = WEBCRYPTO_HASH.get(hash);
  if (!webCryptoHash) {
    throw new Error("The selected hash algorithm is not supported.");
  }

  const secretBytes = base32ToBytes(secret);
  const unixSeconds = Math.floor(timestamp / 1000);
  if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) {
    throw new Error("The device clock returned an invalid time.");
  }

  const counter = BigInt(Math.floor(unixSeconds / period));
  const counterBytes = new Uint8Array(8);
  let remaining = counter;
  for (let index = counterBytes.length - 1; index >= 0; index -= 1) {
    counterBytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable. Open this site over HTTPS in a modern browser.");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: { name: webCryptoHash } },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) * 0x1000000) +
    (signature[offset + 1] * 0x10000) +
    (signature[offset + 2] * 0x100) +
    signature[offset + 3];
  const code = String(binary % (10 ** digits)).padStart(digits, "0");
  const secondsRemaining = period - (unixSeconds % period);

  return { code, secondsRemaining };
}
