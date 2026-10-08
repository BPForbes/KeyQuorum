// The console's in-browser provisioning: what its form accepts, what the
// WebAssembly's result becomes, and what it tells the operator to do next,
// all without a DOM.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BACKUP_PRIVATE_FILE, PRIVATE_FILES, backupFilesOf, backupNextSteps, expiryText, filesOf, loadProvisioner, nextSteps, problems, publicZip, utcText } from "../public/provision.js";

const PUBLIC = join(fileURLToPath(new URL("..", import.meta.url)), "public");

const TODAY = new Date("2026-10-08T12:00:00Z");
const good = { providerId: "Acme Security Services", serial: "KQP-000001", expiresAt: "2027-10-08" };

test("the form needs a provider id, a revocable serial and an expiry after today", () => {
  assert.deepEqual(problems(good, TODAY), []);
  assert.match(problems({ ...good, providerId: " " }, TODAY)[0], /provider id is needed/);
  assert.match(problems({ ...good, providerId: "x".repeat(201) }, TODAY)[0], /longer than 200/);
  assert.match(problems({ ...good, serial: "no spaces" }, TODAY)[0], /serial is needed/);
  assert.match(problems({ ...good, serial: "-leading" }, TODAY)[0], /serial is needed/);
  assert.match(problems({ ...good, expiresAt: "" }, TODAY)[0], /expiry date is needed/);
  assert.match(problems({ ...good, expiresAt: "2026-10-08" }, TODAY)[0], /day after today/);
  assert.equal(problems({ providerId: "", serial: "", expiresAt: "" }, TODAY).length, 3);
});

test("times are written the way the relay's certificates read them", () => {
  assert.equal(utcText(TODAY), "2026-10-08 12:00:00");
  assert.equal(expiryText("2027-10-08"), "2027-10-08 23:59:59");
});

const hex = (fill) => fill.repeat(32);
const result = JSON.stringify({
  root_key: hex("0a"),
  root_pub: hex("0b"),
  relay_key: hex("0c"),
  relay_pub: hex("0d"),
  certificate_base64: Buffer.from("KQPC-cert").toString("base64"),
  package_base64: Buffer.from("KQPK-pkg").toString("base64"),
});

test("the result becomes the six files host provision writes, the private two named as such", () => {
  const { rootPub, files } = filesOf(result);
  assert.equal(rootPub, hex("0b"));
  assert.deepEqual(files.map((f) => f.name), ["root.key", "relay.key", "root.pub", "relay.pub", "provider.kqcert", "provider-info.kqpkg"]);
  assert.deepEqual(files.filter((f) => f.private).map((f) => f.name), PRIVATE_FILES);
  const text = (name) => Buffer.from(files.find((f) => f.name === name).bytes).toString();
  assert.equal(text("root.key"), `${hex("0a")}\n`, "a hex line, as host provision writes it");
  assert.equal(text("relay.key"), `${hex("0c")}\n`);
  assert.equal(text("provider.kqcert"), "KQPC-cert");
  assert.equal(text("provider-info.kqpkg"), "KQPK-pkg");
});

test("a result whose keys are not 64-character hex is refused", () => {
  for (const name of ["root_key", "root_pub", "relay_key", "relay_pub"]) {
    const broken = { ...JSON.parse(result), [name]: "abc" };
    assert.throws(() => filesOf(JSON.stringify(broken)), new RegExp(name));
  }
});

test("the public zip holds only the public files", () => {
  const { files } = filesOf(result);
  const zip = Buffer.from(publicZip(files, TODAY)).toString("latin1");
  for (const name of ["root.pub", "relay.pub", "provider.kqcert", "provider-info.kqpkg"]) assert.ok(zip.includes(name), name);
  for (const name of PRIVATE_FILES) assert.ok(!zip.includes(name), `${name} is never in the zip`);
  assert.ok(!zip.includes(hex("0a")) && !zip.includes(hex("0c")), "no private key in the zip");
});

test("the next steps name the deploy variable, the two secrets and the client pin, and no value but the public root", () => {
  const steps = nextSteps(hex("0b")).join("\n");
  assert.match(steps, /PROVIDER_ROOT/);
  assert.match(steps, /wrangler secret put RELAY_PRIVATE_KEY < relay\.key/);
  assert.match(steps, /wrangler secret put RELAY_CERTIFICATE/);
  assert.match(steps, /KEYQUORUM_PROVIDER_ROOT/);
  assert.match(steps, /never commit it/);
  assert.match(steps, /Keep root\.key offline/);
  assert.doesNotMatch(steps, /[0-9a-f]{64}/, "the root is shown by the page, not pasted into the steps");
});

test("the WebAssembly is loaded once, from the console's own files, initialised before use, and gives both functions", async () => {
  let loads = 0;
  let inits = 0;
  const importer = async (path) => {
    loads += 1;
    assert.equal(path, "./provision-wasm/keyquorum_console.js");
    return { default: async () => (inits += 1), provision_identity: () => "{}", backup_keygen: () => "{}" };
  };
  const first = await loadProvisioner(importer);
  const second = await loadProvisioner(importer);
  assert.equal(first, second);
  assert.deepEqual(Object.keys(first).sort(), ["backup_keygen", "provision_identity"]);
  assert.deepEqual([loads, inits], [1, 1]);
});

test("the backup keypair becomes backup.key (private) and backup.pub, and its next steps name the variable, never a value", () => {
  const { backupPub, files } = backupFilesOf(JSON.stringify({ backup_key: hex("0e"), backup_pub: hex("0f") }));
  assert.equal(backupPub, hex("0f"));
  assert.deepEqual(files.map((f) => [f.name, f.private]), [[BACKUP_PRIVATE_FILE, true], ["backup.pub", false]]);
  assert.equal(Buffer.from(files[0].bytes).toString(), `${hex("0e")}\n`);
  assert.throws(() => backupFilesOf(JSON.stringify({ backup_key: "abc", backup_pub: hex("0f") })), /backup_key/);
  const steps = backupNextSteps(hex("0f")).join("\n");
  assert.match(steps, /BACKUP_RECIPIENT/);
  assert.match(steps, /host backup inspect \| restore/);
  assert.doesNotMatch(steps, /[0-9a-f]{64}/);
});

test("the Status page's backup setup makes the keypair in the browser and sends nothing", () => {
  const status = readFileSync(join(PUBLIC, "view-status.js"), "utf8");
  assert.match(status, /Make the backup keypair in this browser/);
  assert.match(status, /BACKUP_RECIPIENT/);
  assert.match(status, /never upload it anywhere, this console included/);
  // The one fetch on the page is the status read, through api.js.
  assert.doesNotMatch(status, /fetch\(/);
  assert.equal(status.split("await get(").length - 1, 1, "one API read, no upload");
});
