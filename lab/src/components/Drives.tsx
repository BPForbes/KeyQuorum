import type { Act } from "../App";
import type { Snapshot } from "../api/types";

export function Drives({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  return (
    <section className="panel" data-panel="usb" aria-labelledby="usb-heading">
      <h2 id="usb-heading" className="panel-title">
        Mock USB devices
      </h2>
      <p className="muted small">
        Each drive is a KeyQuorum device container: a signed <code>device.kq</code> with its own device id, plus one
        Argon2id-sealed token per slot. An inserted drive presents its slots to every unlock.
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
            <p className="small">
              Slots:{" "}
              {drive.slots.map((slot) => (
                <span key={slot.label} className="tag">
                  {slot.label} {slot.holder}
                </span>
              ))}
            </p>
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
