// The console's file tool reads only public framing and refuses private key
// material; its zip is a real zip; its fingerprint is the Rust one.
import assert from "node:assert/strict";
import test from "node:test";
import { MAX_FILE_BYTES, classify, fromBase64, looksLikeRawKey, readEnrollment, readPackage, toBase64 } from "../public/files.js";
import { crc32, makeZip } from "../public/zip.js";

// Held to the same bytes and fingerprint as src/enrollment/tests.rs.
const VECTOR = "4b5152510103030303030303030303030303030303000000006ab13b800005616c6963650909090909090909090909090909090909090909090909090909090909090909ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca62aa7c55be83e8a5f1ac1242dfbe358318c44b445d1d2b022bcc3a987d2f4610c3852bee70f88f85ea6ceb087d2ad9e62bdd14cf54841778330a03a42b53002";
const FINGERPRINT = "704c1175 74c5821a 1d26faf2 001ba951 b4df212c e32f5e24 52bf7e58 82456c3c";
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const text = (value) => new TextEncoder().encode(value);

test("an enrollment request is read and fingerprinted the way the client's own command does", async () => {
  const request = bytes(VECTOR);
  assert.equal(classify(request, "alice.kqreq").kind, "enrollment");
  const read = await readEnrollment(request);
  assert.equal(read.label, "alice");
  assert.equal(read.deviceId, "03".repeat(16));
  assert.equal(read.fingerprint, FINGERPRINT);
});

test("a malformed or padded enrollment request is not read", async () => {
  const good = bytes(VECTOR);
  await assert.rejects(readEnrollment(good.subarray(0, good.length - 1)));
  await assert.rejects(readEnrollment(new Uint8Array([...good, 0])));
  await assert.rejects(readEnrollment(text("KQRQ nonsense")));
});

test("each public artifact is named by its own magic, whatever the file is called", () => {
  for (const [magic, kind] of [["KQPC", "certificate"], ["KQRL", "revocation"], ["KQPL", "policy"], ["KQPK", "package"]]) {
    const found = classify(new Uint8Array([...text(magic), 1, 1, 0, 0]), "renamed.txt");
    assert.equal(found.accepted, true, magic);
    assert.equal(found.kind, kind);
  }
});

test("sealed keys are accepted as sealed and every other sealed file is not handled", () => {
  const frame = (magic, version, kind) => new Uint8Array([...text(magic), version, kind, 1, 2, 3]);
  assert.equal(classify(frame("KQXB", 1, 4)).kind, "sealed_key");
  assert.equal(classify(frame("KQPB", 2, 20)).kind, "sealed_key_letter");
  assert.equal(classify(frame("KQXB", 1, 4)).visibility, "sealed");
  for (const [magic, version, kind] of [["KQXB", 1, 1], ["KQXB", 1, 3], ["KQPB", 2, 9], ["KQPB", 2, 13]]) {
    assert.equal(classify(frame(magic, version, kind)).accepted, false, `${magic} ${kind}`);
  }
});

test("things the console does not handle, and private key material, are refused without being read further", () => {
  for (const magic of ["KQTF", "KQTX", "KQHS", "KQBS", "KQBN", "KQDV", "KQST"]) {
    assert.equal(classify(new Uint8Array([...text(magic), 1, 0, 0])).accepted, false, magic);
  }
  const hex64 = "ab".repeat(32);
  assert.equal(looksLikeRawKey(text(hex64)), true);
  assert.equal(looksLikeRawKey(text(`${hex64}\n`)), true);
  assert.equal(looksLikeRawKey(text("A".repeat(43) + "=")), true);
  assert.equal(looksLikeRawKey(text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")), true);
  assert.equal(looksLikeRawKey(bytes(VECTOR)), false);
  for (const [name, content] of [["relay.key", text("x")], ["device.skey", text("x")], ["root.pem", text("x")], ["any.txt", text(hex64)]]) {
    const found = classify(content, name);
    assert.equal(found.accepted, false, name);
    assert.equal(found.kind, "refused");
  }
  assert.equal(classify(new Uint8Array(0)).accepted, false);
  assert.equal(classify(new Uint8Array(MAX_FILE_BYTES + 1)).accepted, false);
  assert.equal(classify(text("hello world")).accepted, false);
});

// A package header as the Rust codec writes it, with the signature unchecked.
function packageBytes(purpose, components) {
  const parts = [text("KQPK"), Uint8Array.of(1, purpose), new Uint8Array(16).fill(5)];
  const times = new DataView(new ArrayBuffer(16));
  times.setBigUint64(0, 1000n);
  times.setBigUint64(8, 2000n);
  parts.push(new Uint8Array(times.buffer), new Uint8Array(32).fill(6), Uint8Array.of(0, components.length));
  for (const [kind, size] of components) {
    const length = new DataView(new ArrayBuffer(4));
    length.setUint32(0, size);
    parts.push(Uint8Array.of(kind), new Uint8Array(32), new Uint8Array(length.buffer), new Uint8Array(size));
  }
  parts.push(new Uint8Array(64));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

test("the user type of a package follows its purpose and its parts are listed", () => {
  const client = readPackage(packageBytes(1, [[1, 10], [4, 20]]));
  assert.equal(client.userType, "CLIENT");
  assert.equal(client.purpose, "client_setup");
  assert.deepEqual(client.components.map((c) => c.kind), ["relay certificate", "sealed API key (.kqkey)"]);
  assert.equal(client.issuedAt, 1000);
  assert.equal(client.expiresAt, 2000);
  assert.equal(readPackage(packageBytes(3, [[1, 10]])).userType, "PROVIDER");
  assert.equal(readPackage(packageBytes(4, [[1, 10]])).userType, "PROVIDER");
  assert.equal(readPackage(packageBytes(2, [[1, 10]])).userType, "CLIENT");
});

test("a cut-short, padded or unknown package is not read", () => {
  const good = packageBytes(1, [[1, 10]]);
  assert.throws(() => readPackage(good.subarray(0, good.length - 70)));
  assert.throws(() => readPackage(new Uint8Array([...good, 0])));
  assert.throws(() => readPackage(packageBytes(9, [[1, 10]])));
  assert.throws(() => readPackage(text("KQPK")));
});

test("base64 round-trips the bytes the console sends and receives", () => {
  const data = Uint8Array.from({ length: 70_000 }, (_, i) => i % 251);
  assert.deepEqual(fromBase64(toBase64(data)), data);
});

// A zip read back by its own structure and checked against its checksums.
function readZip(zip) {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  const end = zip.length - 22;
  assert.equal(view.getUint32(end, true), 0x06054b50);
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  assert.equal(view.getUint32(end + 12, true) + at, end);
  const files = {};
  for (let i = 0; i < count; i += 1) {
    assert.equal(view.getUint32(at, true), 0x02014b50);
    const crc = view.getUint32(at + 16, true);
    const size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const local = view.getUint32(at + 42, true);
    const name = new TextDecoder().decode(zip.subarray(at + 46, at + 46 + nameLength));
    assert.equal(view.getUint32(local, true), 0x04034b50);
    const start = local + 30 + view.getUint16(local + 26, true);
    const content = zip.subarray(start, start + size);
    assert.equal(crc32(content), crc, name);
    files[name] = content;
    at += 46 + nameLength;
  }
  return files;
}

test("the zip holds exactly the files given, byte for byte, with correct checksums", () => {
  const files = [
    { name: "provider.kqpkg", bytes: bytes(VECTOR) },
    { name: "provider.kqcert", bytes: text("KQPC certificate bytes") },
    { name: "README.txt", bytes: text("public files only") },
  ];
  const read = readZip(makeZip(files, new Date("2026-10-07T12:00:00Z")));
  assert.deepEqual(Object.keys(read).sort(), ["README.txt", "provider.kqcert", "provider.kqpkg"]);
  for (const file of files) assert.deepEqual(read[file.name], file.bytes);
  assert.equal(crc32(text("123456789")), 0xcbf43926);
});

test("a zip never takes a name that could leave its folder, or a repeat", () => {
  const one = (name) => () => makeZip([{ name, bytes: text("x") }]);
  for (const name of ["../x", "a/b", "/abs", ".hidden", "", "a\\b", "x".repeat(101), "with space"]) {
    assert.throws(one(name), name);
  }
  assert.throws(() => makeZip([{ name: "a", bytes: text("x") }, { name: "a", bytes: text("y") }]));
  assert.throws(() => makeZip([]));
});
