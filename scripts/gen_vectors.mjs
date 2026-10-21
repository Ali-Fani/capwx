// Regenerate tests/vectors/*.json from a checkout of tiagozip/cap at the pinned commit.
//
// Usage (from the repository root):
//   CAP_CHECKOUT=/path/to/cap node scripts/gen_vectors.mjs
//
// The script imports the real upstream files (core/src/*.js) from CAP_CHECKOUT,
// so vectors always come from the reference implementation, never from copies.
// Internal helpers that upstream does not export (hashWith, domSumMock) are
// extracted from the source text of core/src/instrumentation.js.
//
// Outputs (committed):
//   tests/vectors/crypto.json          jwt / gcm / pow vectors
//   tests/vectors/hashwx.json          HashWX vectors (tevador test seeds)
//   tests/vectors/instrumentation.json hashWith / domSum vectors
//
// tests/vectors/vectors.json is hand-maintained (plan 13.1). This script checks
// its hashWith / domSum / hashwx / pow / jwt / gcm entries against upstream and
// fails if they disagree.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import crypto from "node:crypto";

const PINNED_COMMIT = "29bbe6fbe284786cdb0d4489e5040aee6042b2a4";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const outDir = path.join(repoRoot, "tests", "vectors");

const checkout = process.env.CAP_CHECKOUT;
if (!checkout) {
  console.error("CAP_CHECKOUT is not set. Point it at a checkout of tiagozip/cap.");
  process.exit(2);
}

const head = execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
if (head !== PINNED_COMMIT) {
  console.error(`checkout is at ${head}, expected pinned ${PINNED_COMMIT}`);
  process.exit(2);
}

const srcDir = path.join(checkout, "core", "src");
const load = (file) => import(pathToFileURL(path.join(srcDir, file)).href);
const cryptoJs = await load("crypto.js");
const hashwxJs = await load("hashwx.js");

// Extract a top-level function's source by brace matching (the two helpers are
// small and contain no braces inside string literals).
function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found in instrumentation.js`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`unterminated function ${name}`);
}

const instrSource = fs.readFileSync(path.join(srcDir, "instrumentation.js"), "utf8");
// domSumMock depends on the top-level helper `const toInt32 = (n) => n | 0;`.
const toInt32Line = instrSource.match(/^const toInt32 = .*$/m)?.[0];
if (!toInt32Line) throw new Error("toInt32 helper not found in instrumentation.js");
const hashWith = new Function(`${extractFunction(instrSource, "hashWith")}; return hashWith;`)();
const domSumMock = new Function(
  `${toInt32Line}\n${extractFunction(instrSource, "domSumMock")}; return domSumMock;`,
)();

// ---- instrumentation helpers ------------------------------------------------

const HASHWITH_INPUTS = [
  [1, "webdriver"],
  [2147483646, "[native code]"],
  [123456789, "[object Navigator]"],
  [987654321, ""],
  [42, "HeadlessChrome"],
];
const DOMSUM_INPUTS = [
  [10, 20, 30],
  [250, 250, 250],
  [-5, 7, -300],
  [-2147483648, 2147483647, 0],
  [123, -1, 99],
];

const hashWithVectors = HASHWITH_INPUTS.map(([seed, s]) => [seed, s, hashWith(seed)(s)]);
const domSumVectors = DOMSUM_INPUTS.map(([x, y, z]) => [x, y, z, domSumMock(x, y, z)]);

// ---- crypto vectors --------------------------------------------------------

const SECRET = "test-secret-0123456789abcdef";
const FMT2_INFO = "cap:fmt2-v1";
const gcmPayload = {
  expected: [{ protocol: "sha256-pow", salt: "ab", target: "0000" }],
};
const gcmBlob = cryptoJs.encryptGcm(gcmPayload, SECRET, FMT2_INFO);
const jwtPayload = { f: 2, n: "00ff", exp: 1893456000000, iat: 1893455400000, sk: "login" };
const jwtToken = cryptoJs.jwtSign(jwtPayload, SECRET);

const POW_INPUTS = [
  ["0", "salt"],
  ["00", "salt"],
  ["000a", "salt"],
  ["f", "salt"],
];
// smallest nonce whose sha256(salt + nonce) hex starts with target
const powVectors = POW_INPUTS.map(([target, salt]) => {
  for (let nonce = 0; ; nonce++) {
    const hex = crypto.createHash("sha256").update(salt + nonce).digest("hex");
    if (hex.startsWith(target)) return [target, salt, nonce];
  }
});

// ---- hashwx vectors --------------------------------------------------------

const hashwxState = await hashwxJs.hashwxReady();
const padSeed = (ascii) => {
  const buf = new Uint8Array(32);
  buf.set(Buffer.from(ascii, "ascii").subarray(0, 32));
  return buf;
};
const HASHWX_INPUTS = [
  ["This is a test seed for hashwx", 0n],
  ["This is a test seed for hashwx", 123456n],
  ["Lorem ipsum dolor sit amet", 123456n],
  ["Lorem ipsum dolor sit amet", 987654321123456789n],
];
// Nonces are kept as decimal strings: values above 2**53 are not exact JS numbers.
const hashwxVectors = HASHWX_INPUTS.map(([seedStr, nonce]) => {
  const h = hashwxJs.hashwxHash(hashwxState, padSeed(seedStr), nonce);
  return [seedStr, nonce.toString(), BigInt.asUintN(64, BigInt(h)).toString(16).padStart(16, "0")];
});

// ---- consistency with the hand-written vectors.json ------------------------

const handWritten = JSON.parse(fs.readFileSync(path.join(outDir, "vectors.json"), "utf8"));
const mismatch = (what, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`${what} disagrees with vectors.json:\n  upstream ${JSON.stringify(got)}\n  file     ${JSON.stringify(want)}`);
  }
};
mismatch("hashWith", hashWithVectors, handWritten.hashWith);
mismatch("domSum", domSumVectors, handWritten.domSum);
mismatch("pow", powVectors, handWritten.pow);
// vectors.json stores nonces as JSON numbers, which cannot hold the largest nonce
// exactly, so only the seed and hash columns are compared.
mismatch(
  "hashwx",
  hashwxVectors.map(([s, , h]) => [s, h]),
  handWritten.hashwx.map(([s, , h]) => [s, h]),
);
const jwtVerified = cryptoJs.jwtVerify(handWritten.jwt, handWritten.secret);
mismatch("jwt payload", jwtVerified, jwtPayload);
const gcmVerified = cryptoJs.decryptGcm(handWritten.gcm, handWritten.secret, FMT2_INFO);
mismatch("gcm payload", gcmVerified, gcmPayload);

// ---- write outputs ---------------------------------------------------------

const write = (name, obj) => {
  fs.writeFileSync(path.join(outDir, name), JSON.stringify(obj, null, 2) + "\n");
  console.log(`wrote tests/vectors/${name}`);
};

write("crypto.json", {
  upstream_commit: PINNED_COMMIT,
  secret: SECRET,
  jwt: jwtToken,
  jwt_payload: jwtPayload,
  gcm: gcmBlob,
  gcm_info: FMT2_INFO,
  gcm_payload: gcmPayload,
  pow: powVectors,
});
write("hashwx.json", {
  upstream_commit: PINNED_COMMIT,
  hashwx: hashwxVectors,
});
write("instrumentation.json", {
  upstream_commit: PINNED_COMMIT,
  hashWith: hashWithVectors,
  domSum: domSumVectors,
});
