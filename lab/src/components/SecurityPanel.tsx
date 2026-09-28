import { useId, useState } from "react";
import type { Act } from "../App";
import type { ActionResult, FileShareView, PasswordFileView, Snapshot } from "../api/types";
import { formatUtc } from "../explorerTypes";
import { FileViewer } from "./FileViewer";

/** Lock a note as a password-protected file with a password (and optional PIN) the person types themselves. */
function LockNoteForm({ act }: { act: Act }) {
  const id = useId();
  const [name, setName] = useState("");
  const [contents, setContents] = useState("");
  const [password, setPassword] = useState("");
  const [wantsPin, setWantsPin] = useState(false);
  const [pin, setPin] = useState("");

  return (
    <form
      className="lock-note-form"
      data-testid="password-lock"
      onSubmit={(event) => {
        event.preventDefault();
        if (!name.trim() || !contents.trim() || !password) return;
        const result = act((client) => client.lockPasswordFile(name.trim(), contents, password, wantsPin ? pin : undefined));
        if (result?.ok) {
          setName("");
          setContents("");
          setPassword("");
          setPin("");
          setWantsPin(false);
        }
      }}
    >
      <label htmlFor={`${id}-name`}>File name</label>
      <input id={`${id}-name`} value={name} onChange={(event) => setName(event.target.value)} placeholder="my-note.txt" required />

      <label htmlFor={`${id}-contents`}>Contents</label>
      <textarea
        id={`${id}-contents`}
        value={contents}
        onChange={(event) => setContents(event.target.value)}
        rows={3}
        placeholder="Whatever you want protected with a password"
        required
      />

      <label htmlFor={`${id}-password`}>Your own lock password</label>
      <input
        id={`${id}-password`}
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        autoComplete="new-password"
        required
      />

      <label className="checkbox-row">
        <input type="checkbox" checked={wantsPin} onChange={(event) => setWantsPin(event.target.checked)} />
        Also require a 4-digit PIN
      </label>
      {wantsPin ? (
        <>
          <label htmlFor={`${id}-pin`} className="visually-hidden">
            PIN
          </label>
          <input
            id={`${id}-pin`}
            value={pin}
            onChange={(event) => setPin(event.target.value)}
            inputMode="numeric"
            pattern="[0-9]{4}"
            maxLength={4}
            placeholder="0000"
            required
          />
        </>
      ) : null}

      <button type="submit" className="btn btn-primary">
        Lock with my password
      </button>
    </form>
  );
}

function UnlockPasswordFile({ file, act }: { file: PasswordFileView; act: Act }) {
  const id = useId();
  const [password, setPassword] = useState("");
  const [pin, setPin] = useState("");
  const [viewing, setViewing] = useState<ActionResult | null>(null);

  return (
    <>
      <form
        className="unlock-note-form"
        onSubmit={(event) => {
          event.preventDefault();
          const result = act((client) => client.unlockPasswordFile(file.id, password, file.pinProtected ? pin : undefined));
          if (result) setViewing(result);
          setPassword("");
          setPin("");
        }}
      >
        <label htmlFor={`${id}-password`} className="visually-hidden">
          Password for {file.name}
        </label>
        <input
          id={`${id}-password`}
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="Password"
          required
        />
        {file.pinProtected ? (
          <input
            value={pin}
            onChange={(event) => setPin(event.target.value)}
            placeholder="PIN"
            inputMode="numeric"
            maxLength={4}
            required
          />
        ) : null}
        <button type="submit" className="btn small-btn">
          Unlock
        </button>
      </form>
      {viewing ? <FileViewer result={viewing} fileName={file.name} onClose={() => setViewing(null)} /> : null}
    </>
  );
}

/** Seal a copy of a password-locked file to another lab user's public key. */
function ExportFileForm({ file, snapshot, act }: { file: PasswordFileView; snapshot: Snapshot; act: Act }) {
  const id = useId();
  const others = snapshot.users.filter((user) => user.label !== file.owner);
  const [recipient, setRecipient] = useState(others[0]?.label ?? "");
  const [password, setPassword] = useState("");
  const [open, setOpen] = useState(false);

  if (others.length === 0) return null;

  return (
    <>
      <button type="button" className="btn small-btn" onClick={() => setOpen((value) => !value)}>
        {open ? "Cancel export" : "Export…"}
      </button>
      {open ? (
        <form
          className="export-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!password) return;
            const result = act((client) => client.exportFile(file.id, recipient, password));
            if (result?.ok) {
              setPassword("");
              setOpen(false);
            }
          }}
        >
          <label htmlFor={`${id}-recipient`}>Recipient</label>
          <select id={`${id}-recipient`} value={recipient} onChange={(event) => setRecipient(event.target.value)}>
            {others.map((user) => (
              <option key={user.label} value={user.label}>
                {user.name}
              </option>
            ))}
          </select>
          <label htmlFor={`${id}-password`} className="visually-hidden">
            {file.name}&rsquo;s lock password
          </label>
          <input
            id={`${id}-password`}
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="This file's lock password"
            required
          />
          <button type="submit" className="btn small-btn">
            Seal bundle
          </button>
        </form>
      ) : null}
    </>
  );
}

/** Create a time-limited, revocable share link for a password-locked file. */
function CreateShareForm({ file, act }: { file: PasswordFileView; act: Act }) {
  const id = useId();
  const [ttlSeconds, setTtlSeconds] = useState(3600);
  const [wantsPin, setWantsPin] = useState(false);
  const [pin, setPin] = useState("");
  const [open, setOpen] = useState(false);
  const [viewing, setViewing] = useState<ActionResult | null>(null);

  return (
    <>
      <button type="button" className="btn small-btn" onClick={() => setOpen((value) => !value)}>
        {open ? "Cancel share" : "Share…"}
      </button>
      {open ? (
        <form
          className="share-form"
          onSubmit={(event) => {
            event.preventDefault();
            const result = act((client) => client.createFileShare(file.id, ttlSeconds, wantsPin ? pin : undefined));
            if (result) setViewing(result);
            if (result?.ok) {
              setOpen(false);
              setPin("");
              setWantsPin(false);
            }
          }}
        >
          <label htmlFor={`${id}-ttl`}>Link lasts (seconds)</label>
          <input
            id={`${id}-ttl`}
            type="number"
            min={1}
            value={ttlSeconds}
            onChange={(event) => setTtlSeconds(Number(event.target.value))}
            required
          />
          <label className="checkbox-row">
            <input type="checkbox" checked={wantsPin} onChange={(event) => setWantsPin(event.target.checked)} />
            Also require a 4-digit PIN
          </label>
          {wantsPin ? (
            <input
              value={pin}
              onChange={(event) => setPin(event.target.value)}
              inputMode="numeric"
              pattern="[0-9]{4}"
              maxLength={4}
              placeholder="0000"
              required
            />
          ) : null}
          <button type="submit" className="btn small-btn">
            Create link
          </button>
        </form>
      ) : null}
      {viewing ? (
        <FileViewer result={viewing} fileName={`Share link for ${file.name}`} onClose={() => setViewing(null)} />
      ) : null}
    </>
  );
}

function ExportedBundles({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [viewing, setViewing] = useState<ActionResult | null>(null);
  const mine = snapshot.exports.filter((bundle) => bundle.owner === snapshot.activeUser.label);
  return (
    <div>
      {mine.length === 0 ? (
        <p className="small muted">None yet.</p>
      ) : (
        <ul className="mono-list">
          {mine.map((bundle) => (
            <li key={bundle.id}>
              <div>
                <strong>{bundle.fileName}</strong>{" "}
                <span className="muted small">
                  · for {bundle.recipientName} · {bundle.size} bytes · sealed {formatUtc(bundle.createdAt)}
                </span>
              </div>
              <button
                type="button"
                className="btn small-btn"
                onClick={() => {
                  const result = act((client) => client.viewExport(bundle.id));
                  if (result) setViewing(result);
                }}
              >
                View sealed bytes
              </button>
            </li>
          ))}
        </ul>
      )}
      {viewing ? (
        <FileViewer result={viewing} fileName={viewing.opened?.name ?? "bundle"} onClose={() => setViewing(null)} />
      ) : null}
    </div>
  );
}

/** Redeem a file share's bearer token: not scoped to any lab user — whoever has the token may use it. */
function RedeemShareForm({ share, act }: { share: FileShareView; act: Act }) {
  const id = useId();
  const [token, setToken] = useState("");
  const [pin, setPin] = useState("");
  const [result, setResult] = useState<ActionResult | null>(null);

  if (share.revoked) {
    return <p className="small muted">Revoked.</p>;
  }

  return (
    <form
      className="redeem-share-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!token) return;
        const outcome = act((client) => client.redeemFileShare(share.id, token, pin || undefined));
        if (outcome) setResult(outcome);
        setToken("");
        setPin("");
      }}
    >
      <label htmlFor={`${id}-token`} className="visually-hidden">
        Share token for {share.fileName}
      </label>
      <input
        id={`${id}-token`}
        value={token}
        onChange={(event) => setToken(event.target.value)}
        placeholder="Paste the token you were given"
        required
      />
      {share.pinProtected ? (
        <input
          value={pin}
          onChange={(event) => setPin(event.target.value)}
          placeholder="PIN"
          inputMode="numeric"
          maxLength={4}
        />
      ) : null}
      <button type="submit" className="btn small-btn">
        Redeem
      </button>
      {result ? <p className={`small ${result.ok ? "muted" : "viewer-denied-title"}`}>{result.message}</p> : null}
    </form>
  );
}

function ShareLinks({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  return (
    <div>
      {snapshot.fileShares.length === 0 ? (
        <p className="small muted">None yet.</p>
      ) : (
        <ul className="password-file-list">
          {snapshot.fileShares.map((share) => (
            <li key={share.id}>
              <div>
                <strong>{share.fileName}</strong>{" "}
                <span className="muted small">
                  · from {share.owner} · expires {formatUtc(share.expiresAt)}
                  {share.pinProtected ? " · PIN required" : ""}
                  {share.revoked ? " · revoked" : ""}
                </span>
              </div>
              <RedeemShareForm share={share} act={act} />
              {share.owner === snapshot.activeUser.label && !share.revoked ? (
                <button
                  type="button"
                  className="btn small-btn"
                  onClick={() => act((client) => client.revokeFileShare(share.id))}
                >
                  Revoke
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ProvisionSlotForm({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const id = useId();
  const connected = snapshot.drives.filter((drive) => drive.connected);
  const [driveId, setDriveId] = useState(connected[0]?.id ?? "");
  const [label, setLabel] = useState("");
  const [passphrase, setPassphrase] = useState("");

  if (connected.length === 0) {
    return <p className="small muted">Insert a mock USB drive (see USB devices) before provisioning a new slot on it.</p>;
  }

  return (
    <form
      className="provision-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!label.trim() || !passphrase) return;
        const result = act((client) => client.provisionSlot(driveId, label.trim(), passphrase));
        if (result?.ok) {
          setLabel("");
          setPassphrase("");
        }
      }}
    >
      <label htmlFor={`${id}-drive`}>Drive</label>
      <select id={`${id}-drive`} value={driveId} onChange={(event) => setDriveId(event.target.value)}>
        {connected.map((drive) => (
          <option key={drive.id} value={drive.id}>
            {drive.name}
          </option>
        ))}
      </select>

      <label htmlFor={`${id}-label`}>New slot label</label>
      <input id={`${id}-label`} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="e.g. M.F" required />

      <label htmlFor={`${id}-pass`}>Your own passphrase</label>
      <input
        id={`${id}-pass`}
        type="password"
        value={passphrase}
        onChange={(event) => setPassphrase(event.target.value)}
        autoComplete="new-password"
        required
      />

      <button type="submit" className="btn btn-primary">
        Provision slot
      </button>
      <p className="small muted">
        Mints a fresh encryption/signing keypair sealed under your passphrase (<code>keyquorum-device provision</code>). Registering
        it into the org tree is a separate step, same as on a real machine.
      </p>
    </form>
  );
}

/** Insert a slot already provisioned on an inserted drive as a new leaf under an existing org-tree node. */
function RegisterLeafForm({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const id = useId();
  const connected = snapshot.drives.filter((drive) => drive.connected);
  const [driveId, setDriveId] = useState(connected[0]?.id ?? "");
  const [slotLabel, setSlotLabel] = useState("");
  const splitNodes = snapshot.tree.nodes.filter((node) => node.kind === "split");
  const [parent, setParent] = useState(splitNodes[0]?.label ?? "");
  const [result, setResult] = useState<ActionResult | null>(null);

  if (connected.length === 0 || splitNodes.length === 0) {
    return <p className="small muted">Insert a drive with a provisioned-but-unregistered slot to grow the org tree.</p>;
  }

  return (
    <form
      className="provision-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!slotLabel.trim() || !parent) return;
        const outcome = act((client) => client.registerLeaf(driveId, slotLabel.trim(), parent));
        if (outcome) setResult(outcome);
        if (outcome?.ok) setSlotLabel("");
      }}
    >
      <label htmlFor={`${id}-drive`}>Drive</label>
      <select id={`${id}-drive`} value={driveId} onChange={(event) => setDriveId(event.target.value)}>
        {connected.map((drive) => (
          <option key={drive.id} value={drive.id}>
            {drive.name}
          </option>
        ))}
      </select>

      <label htmlFor={`${id}-slot`}>Provisioned slot label</label>
      <input
        id={`${id}-slot`}
        value={slotLabel}
        onChange={(event) => setSlotLabel(event.target.value)}
        placeholder="e.g. M.S.3"
        required
      />

      <label htmlFor={`${id}-parent`}>Parent node</label>
      <select id={`${id}-parent`} value={parent} onChange={(event) => setParent(event.target.value)}>
        {splitNodes.map((node) => (
          <option key={node.label} value={node.label}>
            {node.label}
          </option>
        ))}
      </select>

      <button type="submit" className="btn btn-primary">
        Register as a new leaf
      </button>
      <p className="small muted">
        Registers the slot&rsquo;s encryption and signing keys (<code>keyquorum device register</code>), binds its
        container (<code>device bind</code>), then adds it under the parent (<code>keyquorum add</code>) — which
        reshares the parent from its existing children&rsquo;s shares, so every currently inserted, active sibling
        under it is offered as recovery material.
      </p>
      {result ? <p className={`small ${result.ok ? "muted" : "viewer-denied-title"}`}>{result.message}</p> : null}
    </form>
  );
}

function Signatures({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [results, setResults] = useState<Record<number, ActionResult>>({});
  if (snapshot.signatures.length === 0) {
    return <p className="small muted">None yet. Sign a public or received file from the File Explorer.</p>;
  }
  return (
    <ul className="mono-list">
      {snapshot.signatures.map((signature) => (
        <li key={signature.id}>
          <div>
            <strong>{signature.fileName}</strong>{" "}
            <span className="muted small">
              · signed by {signature.signerName} ({signature.signer}) · {signature.size} bytes · bridge{" "}
              {signature.bridgeUid.slice(0, 8)}…
            </span>
          </div>
          <button
            type="button"
            className="btn small-btn"
            onClick={() => {
              const outcome = act((client) => client.verifySignature(signature.id));
              if (outcome) setResults((previous) => ({ ...previous, [signature.id]: outcome }));
            }}
          >
            Verify
          </button>
          {results[signature.id] ? (
            <p className={`small ${results[signature.id].ok ? "muted" : "viewer-denied-title"}`}>
              {results[signature.id].message}
            </p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function DeviceLogs({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [viewing, setViewing] = useState<{ result: ActionResult; name: string } | null>(null);
  const connected = snapshot.drives.filter((drive) => drive.connected);
  return (
    <div>
      {connected.length === 0 ? (
        <p className="small muted">No drives are inserted.</p>
      ) : (
        <ul className="mono-list">
          {connected.map((drive) => (
            <li key={drive.id}>
              <button
                type="button"
                className="btn small-btn"
                onClick={() => {
                  const result = act((client) => client.deviceLog(drive.id));
                  if (result) setViewing({ result, name: `${drive.name} device log` });
                }}
              >
                View {drive.name} device log
              </button>
            </li>
          ))}
        </ul>
      )}
      {viewing ? <FileViewer result={viewing.result} fileName={viewing.name} onClose={() => setViewing(null)} /> : null}
    </div>
  );
}

export function SecurityPanel({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const mine = snapshot.passwordFiles.filter((file) => file.owner === snapshot.activeUser.label);
  const status = snapshot.relayStatus;
  return (
    <section className="panel panel-wide" data-panel="security" aria-labelledby="security-heading">
      <h2 id="security-heading" className="panel-title">
        Security &amp; devices
      </h2>

      <div className="security-grid">
        <div>
          <h3>Password-locked files</h3>
          <p className="small muted">
            Protect a note with a password only you choose (<code>keyquorum access password</code>), with an optional 4-digit PIN.
          </p>
          <LockNoteForm act={act} />
          <h4>Your password-locked files</h4>
          {mine.length === 0 ? (
            <p className="small muted">None yet.</p>
          ) : (
            <ul className="password-file-list" data-testid="password-files">
              {mine.map((file) => (
                <li key={file.id}>
                  <div>
                    <strong>{file.name}</strong>{" "}
                    <span className="muted small">
                      · locked {formatUtc(file.createdAt)}
                      {file.pinProtected ? " · PIN required" : ""}
                    </span>
                  </div>
                  <UnlockPasswordFile file={file} act={act} />
                  <div className="password-file-actions">
                    <ExportFileForm file={file} snapshot={snapshot} act={act} />
                    <CreateShareForm file={file} act={act} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div data-testid="exported-bundles">
          <h3>Exported bundles</h3>
          <p className="small muted">
            Portable <code>KQXB</code> bundles you sealed to another lab user&rsquo;s public key (
            <code>keyquorum export file</code>). No import step exists yet, so this only shows the sealed bytes.
          </p>
          <ExportedBundles snapshot={snapshot} act={act} />
        </div>

        <div data-testid="share-links">
          <h3>Share links</h3>
          <p className="small muted">
            Time-limited, revocable links (<code>keyquorum share create-file</code>). A bearer token authorizes
            redemption, not identity — anyone given the token can use it below.
          </p>
          <ShareLinks snapshot={snapshot} act={act} />
        </div>

        <div data-testid="provision-slot">
          <h3>Create a new key</h3>
          <p className="small muted">Provision a fresh slot on an inserted drive, sealed under a passphrase you choose.</p>
          <ProvisionSlotForm snapshot={snapshot} act={act} />
        </div>

        <div data-testid="register-leaf">
          <h3>Register a new leaf</h3>
          <p className="small muted">Take a provisioned slot from &ldquo;minted, not in any tree&rdquo; to a registered leaf under a chosen org-tree node.</p>
          <RegisterLeafForm snapshot={snapshot} act={act} />
        </div>

        <div data-testid="signatures">
          <h3>Signatures</h3>
          <p className="small muted">
            Signed with the cross-department private bridge (<code>keyquorum sign</code>/<code>verify</code>). Only
            Sarah and David are members; Sarah is the only one with a sealed copy of the shared secret in this shared
            store, so only she can sign here — either of them can verify.
          </p>
          <Signatures snapshot={snapshot} act={act} />
        </div>

        <div data-testid="device-logs">
          <h3>Device logs</h3>
          <p className="small muted">The slots and public keys each inserted container reports.</p>
          <DeviceLogs snapshot={snapshot} act={act} />
        </div>

        <div data-testid="relay-status">
          <h3>Relay status</h3>
          <p className="small muted">
            Read-only counts from the lab&rsquo;s in-process mailbox relay at <code>{status.url}</code>.
          </p>
          <dl className="properties-grid">
            <dt>Package letters</dt>
            <dd>{status.packageLetters}</dd>
            <dt>Device letters</dt>
            <dd>{status.deviceLetters}</dd>
            <dt>Published trees</dt>
            <dd>{status.publishedTrees}</dd>
            <dt>Registered devices</dt>
            <dd>{status.registeredDevices}</dd>
            <dt>API keys</dt>
            <dd>{status.apiKeys}</dd>
          </dl>
        </div>
      </div>
    </section>
  );
}
