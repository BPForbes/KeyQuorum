import { useState } from "react";
import type { Act } from "../App";
import type { DeviceDescriptor, Session } from "../api/types";

const HEX_32 = /^[0-9a-f]{32}$/i;

/** `GET /devices/{device_id}`: the public descriptor a device published
 * (`keyquorum device publish`). Needs a `device.pull` or `device.push` key. */
export function DevicesPanel({ session, act }: { session: Session | null; act: Act }) {
  const [deviceId, setDeviceId] = useState("");
  const [device, setDevice] = useState<DeviceDescriptor | null>(null);
  const allowed = session?.scope === "device.pull" || session?.scope === "device.push";
  const valid = HEX_32.test(deviceId.trim());
  return (
    <section className="panel" data-panel="devices" aria-labelledby="devices-heading">
      <h2 id="devices-heading" className="panel-title">
        Device directory
      </h2>
      <p className="small muted">
        Public facts a device published about itself: its id, its verify key and each slot's public keys, signed by
        the device key. The relay answers a <code>device.pull</code> or <code>device.push</code> key; the sealed device
        letters themselves are never shown to anyone but their recipient.
      </p>
      {!session ? (
        <p className="empty">Sign in with a device key.</p>
      ) : !allowed ? (
        <p className="empty">
          This key's scope is <code>{session.scope}</code>; the relay needs <code>device.pull</code> or{" "}
          <code>device.push</code> here.
        </p>
      ) : (
        <form
          className="lookup-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!valid) return;
            void act("Device descriptor fetched", (relay) => relay.device(deviceId.trim().toLowerCase())).then((answer) => setDevice(answer));
          }}
        >
          <label htmlFor="device-id">Device id (32 hex characters)</label>
          <input id="device-id" data-testid="device-id" value={deviceId} onChange={(event) => setDeviceId(event.target.value)} spellCheck={false} />
          <button type="submit" className="btn" disabled={!valid}>
            Look up
          </button>
        </form>
      )}
      {device ? (
        <dl className="facts" data-testid="device-view">
          <div>
            <dt>Device id</dt>
            <dd>
              <code className="hash">{device.device_id}</code>
            </dd>
          </div>
          <div>
            <dt>Verify key</dt>
            <dd>
              <code className="hash">{device.verify_key}</code>
            </dd>
          </div>
          <div>
            <dt>Slots</dt>
            <dd>
              {device.slots.length === 0 ? (
                <span className="muted">none</span>
              ) : (
                <ul className="mono-list">
                  {device.slots.map((slot) => (
                    <li key={slot.label}>
                      <code>{slot.label}</code> · encryption <code className="hash">{slot.encryption_public.slice(0, 16)}…</code> · signing{" "}
                      <code className="hash">{slot.signing_public.slice(0, 16)}…</code>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </div>
          <div>
            <dt>Signature</dt>
            <dd>
              <code className="hash">{device.signature.slice(0, 24)}…</code> <span className="muted small">(checked by the relay when stored)</span>
            </dd>
          </div>
        </dl>
      ) : null}
    </section>
  );
}
