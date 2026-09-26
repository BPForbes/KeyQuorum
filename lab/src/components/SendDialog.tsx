import { useId, useState } from "react";
import type { FileView, Snapshot } from "../api/types";
import { Modal } from "./Modal";

export function SendDialog({
  file,
  snapshot,
  onCancel,
  onSend,
}: {
  file: FileView;
  snapshot: Snapshot;
  onCancel: () => void;
  onSend: (recipientId: string) => void;
}) {
  const id = useId();
  const recipients = snapshot.users.filter((user) => !user.active);
  const [recipient, setRecipient] = useState(recipients.find((user) => user.visible)?.id ?? recipients[0]?.id ?? "");
  return (
    <Modal title={`Send ${file.name}`} onClose={onCancel} labelledBy={`${id}-title`}>
      <form
        className="send-dialog"
        onSubmit={(event) => {
          event.preventDefault();
          onSend(recipient);
        }}
      >
        <label htmlFor={`${id}-recipient`}>Recipient</label>
        <select id={`${id}-recipient`} value={recipient} onChange={(event) => setRecipient(event.target.value)}>
          {recipients.map((user) => (
            <option key={user.id} value={user.id}>
              {user.name} — {user.label}
              {user.visible ? "" : " (outside your slice)"}
            </option>
          ))}
        </select>
        <p className="small">
          Transfer method: KeyQuorum sealed file delivery. The file is signed with your slot, sealed to the
          recipient&rsquo;s registered encryption key as a <code>KQPB</code> letter, and stored at the lab relay,
          which routes on the recipient key alone.
        </p>
        <div className="button-row">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary">
            Send
          </button>
        </div>
      </form>
    </Modal>
  );
}
