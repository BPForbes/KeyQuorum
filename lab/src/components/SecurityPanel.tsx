import { useId, useState } from "react";
import type { Act } from "../App";
import type { ActionResult, PasswordFileView, Snapshot } from "../api/types";
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
            <ul className="password-file-list">
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
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h3>Create a new key</h3>
          <p className="small muted">Provision a fresh slot on an inserted drive, sealed under a passphrase you choose.</p>
          <ProvisionSlotForm snapshot={snapshot} act={act} />
        </div>

        <div>
          <h3>Device logs</h3>
          <p className="small muted">The slots and public keys each inserted container reports.</p>
          <DeviceLogs snapshot={snapshot} act={act} />
        </div>

        <div>
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
