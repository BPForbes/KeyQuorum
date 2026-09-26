import { useId, useState } from "react";
import type { Act } from "../App";
import type { Snapshot } from "../api/types";

function MoveSlot({ label, currentDriveId, snapshot, act }: { label: string; currentDriveId: string; snapshot: Snapshot; act: Act }) {
  const id = useId();
  const targets = snapshot.drives.filter((drive) => drive.id !== currentDriveId);
  const [target, setTarget] = useState(targets[0]?.id ?? "");
  if (targets.length === 0) return null;
  return (
    <form
      className="move-slot"
      onSubmit={(event) => {
        event.preventDefault();
        act((client) => client.moveSlot(label, target));
      }}
    >
      <label htmlFor={id} className="visually-hidden">
        Move {label} to
      </label>
      <select id={id} value={target} onChange={(event) => setTarget(event.target.value)}>
        {targets.map((drive) => (
          <option key={drive.id} value={drive.id}>
            move {label} to {drive.name}
          </option>
        ))}
      </select>
      <button type="submit" className="btn small-btn">
        Move
      </button>
    </form>
  );
}

export function Drives({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  return (
    <section className="panel" data-panel="usb" aria-labelledby="usb-heading">
      <h2 id="usb-heading" className="panel-title">
        Mock USB devices
      </h2>
      <p className="muted small">
        Each drive is a KeyQuorum device container: a signed <code>device.kq</code> with its own device id, plus one
        Argon2id-sealed token per slot. An inserted drive presents its slots to every unlock. Every person starts with
        their own drive; moving a slot onto another (both drives must be inserted) puts two people&rsquo;s tokens in
        one real container — the point at which they start counting as one physical device.
      </p>
      <ul className="drives">
        {snapshot.drives.map((drive) => (
          <li key={drive.id} className="drive" data-connected={drive.connected} data-testid={`drive-${drive.id}`}>
            <div className="drive-head">
              <span className="drive-name">
                <span className="dot" aria-hidden="true">
                  {drive.connected ? "●" : "○"}
                </span>{" "}
                {drive.name}
              </span>
              <span className={drive.connected ? "state-ok" : "state-off"}>
                {drive.connected ? "Connected" : "Not inserted"}
              </span>
            </div>
            <p className="small muted">
              <code>{drive.mount}</code> · device <code>{drive.deviceId.slice(0, 8)}</code>
            </p>
            {drive.slots.length > 0 ? (
              <ul className="slot-list">
                {drive.slots.map((slot) => (
                  <li key={slot.label} className="slot-row">
                    <span className="tag">
                      {slot.label} {slot.holder}
                    </span>
                    <MoveSlot label={slot.label} currentDriveId={drive.id} snapshot={snapshot} act={act} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="small muted">No slots on this drive.</p>
            )}
            {drive.connected && drive.files.length > 0 ? (
              <details className="small">
                <summary>Files on the container</summary>
                <ul className="mono-list">
                  {drive.files.map((file) => (
                    <li key={file}>
                      <code>{file}</code>
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
            <button
              type="button"
              className={drive.connected ? "btn" : "btn btn-primary"}
              onClick={() => act((client) => (drive.connected ? client.ejectDrive(drive.id) : client.insertDrive(drive.id)))}
            >
              {drive.connected ? `Eject ${drive.name}` : `Insert ${drive.name}`}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
