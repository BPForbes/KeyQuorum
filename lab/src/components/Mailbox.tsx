import { useState } from "react";
import type { Act } from "../App";
import type { InboxItemView, SentItemView, Snapshot } from "../api/types";

const INBOX_STATUS: Record<InboxItemView["status"], string> = {
  new: "New · sealed",
  received: "Received · acknowledged",
  rejected: "Rejected by you",
  invalid: "Rejected · failed verification",
};

const SENT_STATUS: Record<SentItemView["status"], string> = {
  delivered: "Delivered to relay · awaiting acknowledgement",
  acknowledged: "Acknowledged by recipient",
  rejected: "Rejected by recipient",
};

type View = "inbox" | "sent" | "approvals";

export function Mailbox({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [view, setView] = useState<View>("inbox");
  const pendingApprovals = snapshot.approvals.filter((item) => item.actionable).length;
  return (
    <section className="panel panel-wide" data-panel="mailbox" aria-labelledby="mailbox-heading">
      <h2 id="mailbox-heading" className="panel-title">
        Inbox and sent
      </h2>
      <div className="segmented" role="group" aria-label="Mailbox view">
        <button type="button" aria-pressed={view === "inbox"} onClick={() => setView("inbox")}>
          Inbox ({snapshot.inbox.length})
        </button>
        <button type="button" aria-pressed={view === "sent"} onClick={() => setView("sent")}>
          Sent ({snapshot.sent.length})
        </button>
        <button type="button" aria-pressed={view === "approvals"} onClick={() => setView("approvals")}>
          Approvals ({pendingApprovals} to answer)
        </button>
      </div>

      {view === "inbox" ? (
        <>
          <p className="small muted">
            Letters the lab relay holds for your key. The relay only knows the recipient key, so sender and file stay
            hidden until you open a letter with your slot.
          </p>
          {snapshot.inbox.length === 0 ? <p className="empty">No letters sealed to you.</p> : null}
          <ul className="mail-list">
            {snapshot.inbox.map((item) => (
              <li key={item.relayId} className="mail-item" data-testid={`inbox-${item.relayId}`}>
                <div>
                  <strong>#{item.relayId}</strong> {item.fileName ?? "sealed letter"}{" "}
                  <span className="muted small">
                    {item.from ? `from ${item.from}` : `${item.bytes} bytes · sender sealed`}
                  </span>
                </div>
                <span className="mail-status">{INBOX_STATUS[item.status]}</span>
                {item.status === "new" ? (
                  <div className="button-row">
                    <button type="button" className="btn btn-primary" onClick={() => act((client) => client.receive(item.relayId))}>
                      Receive #{item.relayId}
                    </button>
                    <button type="button" className="btn" onClick={() => act((client) => client.reject(item.relayId))}>
                      Reject #{item.relayId}
                    </button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {view === "sent" ? (
        <>
          {snapshot.pendingAcks > 0 ? (
            <p className="notice">
              {snapshot.pendingAcks} acknowledgement{snapshot.pendingAcks > 1 ? "s are" : " is"} waiting at the relay,
              sealed to your key.
            </p>
          ) : null}
          <button type="button" className="btn" onClick={() => act((client) => client.refreshInbox())}>
            Check relay for acknowledgements
          </button>
          {snapshot.sent.length === 0 ? <p className="empty">Nothing sent yet.</p> : null}
          <ul className="mail-list">
            {snapshot.sent.map((item) => (
              <li key={item.deliveryId} className="mail-item" data-testid={`sent-${item.relayId}`}>
                <div>
                  <strong>{item.fileName}</strong>{" "}
                  <span className="muted small">
                    to {item.to} ({item.toLabel}) · letter #{item.relayId}
                  </span>
                </div>
                <span className="mail-status">{SENT_STATUS[item.status]}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {view === "approvals" ? (
        <>
          <p className="small muted">
            Files with <code>unlock_approval = parent</code> need the leaf&rsquo;s parent to sign each unlock, bound to
            the exact devices presented.
          </p>
          {snapshot.approvals.length === 0 ? <p className="empty">No approval requests.</p> : null}
          <ul className="mail-list">
            {snapshot.approvals.map((item) => (
              <li key={item.id} className="mail-item">
                <div>
                  <strong>{item.fileName}</strong>{" "}
                  <span className="muted small">
                    leaf {item.leaf} · requested by {item.requestedBy} · approver {item.approver} · devices{" "}
                    {item.devices.join(", ")}
                  </span>
                </div>
                <span className="mail-status">{item.status}</span>
                {item.actionable ? (
                  <div className="button-row">
                    <button type="button" className="btn btn-primary" onClick={() => act((client) => client.answerApproval(item.id, true))}>
                      Approve and sign
                    </button>
                    <button type="button" className="btn" onClick={() => act((client) => client.answerApproval(item.id, false))}>
                      Decline
                    </button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
