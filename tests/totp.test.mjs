import assert from "node:assert/strict";
import test from "node:test";
import { base32ToBytes, generateTotp, parseOtpAuthUri } from "../totp.js";

const sha1Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const sha256Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const sha512Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

test("decodes Base32 test data", () => {
  assert.equal(new TextDecoder().decode(base32ToBytes(sha1Secret)), "12345678901234567890");
});

test("matches RFC 6238 SHA-1 test vectors", async () => {
  assert.equal((await generateTotp({ secret: sha1Secret, digits: 8 }, 59_000)).code, "94287082");
  assert.equal((await generateTotp({ secret: sha1Secret, digits: 8 }, 1_111_111_109_000)).code, "07081804");
  assert.equal((await generateTotp({ secret: sha1Secret, digits: 8 }, 20_000_000_000_000)).code, "65353130");
});

test("matches RFC 6238 SHA-256 and SHA-512 test vectors", async () => {
  assert.equal((await generateTotp({ secret: sha256Secret, digits: 8, algorithm: "SHA256" }, 59_000)).code, "46119246");
  assert.equal((await generateTotp({ secret: sha512Secret, digits: 8, algorithm: "SHA512" }, 59_000)).code, "90693936");
});

test("parses standard TOTP provisioning URIs", () => {
  const parsed = parseOtpAuthUri(
    "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
  );
  assert.deepEqual(parsed, {
    issuer: "Example",
    account: "alice@example.com",
    secret: "JBSWY3DPEHPK3PXP",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  });
});

test("rejects malformed or non-TOTP provisioning URIs", () => {
  assert.throws(() => parseOtpAuthUri("not a uri"), /valid authenticator setup URI/);
  assert.throws(() => parseOtpAuthUri("otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP"), /Only TOTP/);
  assert.throws(() => base32ToBytes("NOT!BASE32"), /not valid Base32/);
});
