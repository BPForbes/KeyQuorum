import { useId, useState } from "react";
import type { Act } from "../App";
import type { ActionResult, Snapshot, TreeNodeView } from "../api/types";

// The only tree label in this lab holding a plaintext authority signing
// key (see `seed::RESTRUCTURE_AUTHORITY`), so reissue and restructure run
// `--as` this label. Reissue is offered on every leaf: the CLI itself
// refuses a node outside this label's subtree.
const RESTRUCTURE_AUTHORITY = "M.A";

/** Reissue a leaf's hardware key onto an already-provisioned replacement token. */
function ReissueForm({ label, snapshot, act }: { label: string; snapshot: Snapshot; act: Act }) {
  const id = useId();
  const connected = snapshot.drives.filter((drive) => drive.connected);
  const [driveId, setDriveId] = useState(connected[0]?.id ?? "");
  const [passphrase, setPassphrase] = useState("");
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<ActionResult | null>(null);

  if (connected.length === 0) return null;

  return (
    <>
      <button type="button" className="btn small-btn" onClick={() => setOpen((value) => !value)}>
        {open ? "Cancel reissue" : "Reissue…"}
      </button>
      {open ? (
        <form
          className="provision-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!passphrase) return;
            const outcome = act((client) => client.reissueKey(label, driveId, passphrase));
            if (outcome) setResult(outcome);
            if (outcome?.ok) {
              setPassphrase("");
              setOpen(false);
            }
          }}
        >
          <label htmlFor={`${id}-drive`}>Replacement drive</label>
          <select id={`${id}-drive`} value={driveId} onChange={(event) => setDriveId(event.target.value)}>
            {connected.map((drive) => (
              <option key={drive.id} value={drive.id}>
                {drive.name}
              </option>
            ))}
          </select>
          <label htmlFor={`${id}-pass`} className="visually-hidden">
            New passphrase for {label}
          </label>
          <input
            id={`${id}-pass`}
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="New passphrase for the replacement token"
            autoComplete="new-password"
            required
          />
          <button type="submit" className="btn small-btn">
            Reissue
          </button>
          <p className="small muted">
            Needs a slot named <code>{label}</code> already provisioned on the chosen drive (Security &amp; devices
            tab), authorized as {RESTRUCTURE_AUTHORITY} (<code>keyquorum reissue</code>).
          </p>
        </form>
      ) : null}
      {result ? <p className={`small ${result.ok ? "muted" : "viewer-denied-title"}`}>{result.message}</p> : null}
    </>
  );
}

function Node({ node, nodes, act, snapshot }: { node: TreeNodeView; nodes: TreeNodeView[]; act: Act; snapshot: Snapshot }) {
  const children = nodes.filter((candidate) => candidate.parent === node.label);
  const tags: string[] = [];
  if (node.activeUser) tags.push("you");
  tags.push(
    node.kind === "split"
      ? `split · ${node.threshold ?? "?"} of ${children.length} · topology only, no share of the org key`
      : "leaf · holds a share of the org key",
  );
  if (!node.visible) tags.push("outside your slice");
  if (node.required) tags.push(node.satisfied ? "required · satisfied" : "required · missing");
  return (
    <li>
      <div
        className="tree-node"
        data-active={node.activeUser || undefined}
        data-visible={node.visible}
        data-required={node.required || undefined}
        data-satisfied={node.satisfied || undefined}
      >
        <span className="tree-label">
          <code>{node.label}</code> {node.person ?? ""}
          {node.role ? <span className="muted"> · {node.role}</span> : null}
        </span>
        <span className="tree-slot">
          {node.slotDrive ? (
            <>
              Personal slot on {node.slotDrive}:{" "}
              <span className={node.slotConnected ? "state-ok" : "state-off"}>
                {node.slotConnected ? "available" : "unavailable (drive ejected)"}
              </span>
            </>
          ) : (
            "No slot"
          )}
        </span>
        <span className="tree-tags">
          {tags.map((tag) => (
            <span key={tag} className="tag">
              {tag}
            </span>
          ))}
        </span>
        {node.kind === "leaf" ? (
          <>
            <button
              type="button"
              className="btn small-btn"
              onClick={() => act((client) => client.revokeKey(node.label))}
              aria-label={`Revoke ${node.label}'s hardware key`}
            >
              Revoke key
            </button>
            <ReissueForm label={node.label} snapshot={snapshot} act={act} />
          </>
        ) : null}
      </div>
      {children.length > 0 ? (
        <ul>
          {children.map((child) => (
            <Node key={child.label} node={child} nodes={nodes} act={act} snapshot={snapshot} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function nodeName(nodes: TreeNodeView[], label: string) {
  const person = nodes.find((node) => node.label === label)?.person;
  return person ? `${label} (${person})` : label;
}

// Each button sends a `keyquorum bridge ...` command line through the lab
// terminal, which parses it with the CLI's own clap definitions and runs
// the CLI's own handler. Nothing about bridges is decided here.
function Connections({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const id = useId();
  const { keyId, nodes, bridges, allowed } = snapshot.tree;
  const run = (args: string) => act((client) => client.runCommand(`keyquorum --db ${snapshot.orgDb} bridge ${args}`));
  const [from, setFrom] = useState(snapshot.activeUser.label);
  const [to, setTo] = useState(nodes.find((node) => node.label !== snapshot.activeUser.label)?.label ?? "");
  const options = nodes.map((node) => (
    <option key={node.label} value={node.label}>
      {nodeName(nodes, node.label)}
    </option>
  ));
  return (
    <div className="bridges" data-testid="bridges">
      <h3 className="bridges-title">Bridges</h3>
      <p className="muted small">
        A bridge is a cross-branch link between two nodes. Linking takes two steps, as with the CLI: a node first
        whitelists a peer with <code>bridge allow</code>, then either side establishes the link with{" "}
        <code>bridge add</code>, which KeyQuorum refuses unless one of the two whitelists names the other. Only
        established links change who can see whom: each end sees the other end and its ancestors. Every button here
        runs the real <code>keyquorum bridge</code> command against org tree key <code>{keyId}</code>; the same
        commands work in the Terminal tab.
      </p>

      <h4 className="small">Established</h4>
      {bridges.length > 0 ? (
        <ul className="bridge-list">
          {bridges.map(([a, b]) => (
            <li key={`${a}-${b}`} data-testid={`bridge-${a}-${b}`}>
              <code>
                {a} ↔ {b}
              </code>
              <button
                type="button"
                className="btn small-btn"
                onClick={() => run(`remove ${keyId} --from ${a} --to ${b}`)}
                aria-label={`Remove bridge ${a} to ${b}`}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="small muted">No established bridges.</p>
      )}

      <h4 className="small">Whitelist</h4>
      {allowed.length > 0 ? (
        <ul className="bridge-list">
          {allowed.map(([node, peer]) => (
            <li key={`${node}-${peer}`} data-testid={`allowed-${node}-${peer}`}>
              <code>
                {node} → {peer}
              </code>
              <button
                type="button"
                className="btn small-btn"
                onClick={() => run(`deny ${keyId} --node ${node} --peer ${peer}`)}
                aria-label={`Deny ${node} bridging to ${peer}`}
              >
                Deny
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="small muted">No whitelist entries.</p>
      )}

      <form className="bridge-form" onSubmit={(event) => event.preventDefault()}>
        <label htmlFor={`${id}-from`}>Node</label>
        <select id={`${id}-from`} value={from} onChange={(event) => setFrom(event.target.value)}>
          {options}
        </select>
        <label htmlFor={`${id}-to`}>Peer</label>
        <select id={`${id}-to`} value={to} onChange={(event) => setTo(event.target.value)}>
          {options}
        </select>
        <div className="button-row">
          <button type="button" className="btn" onClick={() => run(`allow ${keyId} --node ${from} --peer ${to}`)}>
            Allow node → peer
          </button>
          <button type="button" className="btn btn-primary" onClick={() => run(`add ${keyId} --from ${from} --to ${to}`)}>
            Establish bridge
          </button>
        </div>
      </form>
    </div>
  );
}

/** Propose a tree restructure (as the lab's one authority label) and countersign proposals addressed to you. */
function RestructureAdmin({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const [passphrase, setPassphrase] = useState("");
  const [result, setResult] = useState<ActionResult | null>(null);
  const activeLabel = snapshot.activeUser.label;
  const isAuthority = activeLabel === RESTRUCTURE_AUTHORITY;
  const mine = snapshot.pendingRestructures.filter((proposal) => proposal.countersignerLabel === activeLabel);

  if (!isAuthority && mine.length === 0 && snapshot.pendingRestructures.length === 0) return null;

  return (
    <div className="bridges" data-testid="restructure-admin">
      <h3 className="bridges-title">Tree restructure</h3>
      <p className="muted small">
        Republishing the org tree at its next public generation (<code>keyquorum tree restructure</code>) needs a
        parent&rsquo;s countersignature (<code>keyquorum tree countersign</code>) before it takes effect — only{" "}
        {RESTRUCTURE_AUTHORITY} can propose one in this lab.
      </p>
      {isAuthority ? (
        <button
          type="button"
          className="btn"
          onClick={() => {
            const outcome = act((client) => client.proposeRestructure());
            if (outcome) setResult(outcome);
          }}
        >
          Propose restructure as {RESTRUCTURE_AUTHORITY}
        </button>
      ) : null}
      {snapshot.pendingRestructures.length > 0 ? (
        <ul className="bridge-list">
          {snapshot.pendingRestructures.map((proposal) => (
            <li key={`${proposal.treeLabel}-${proposal.generation}`}>
              <code>
                {proposal.authorizerLabel} → {proposal.countersignerLabel}
              </code>{" "}
              <span className="muted small">generation {proposal.generation}, waiting to be countersigned</span>
            </li>
          ))}
        </ul>
      ) : null}
      {mine.length > 0 ? (
        <form
          className="unlock-note-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!passphrase) return;
            const outcome = act((client) => client.countersignRestructure(passphrase));
            if (outcome) setResult(outcome);
            setPassphrase("");
          }}
        >
          <label htmlFor="restructure-countersign-pass" className="visually-hidden">
            Your device passphrase
          </label>
          <input
            id="restructure-countersign-pass"
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="Your device passphrase"
            required
          />
          <button type="submit" className="btn btn-primary">
            Countersign
          </button>
        </form>
      ) : null}
      {result ? <p className={`small ${result.ok ? "muted" : "viewer-denied-title"}`}>{result.message}</p> : null}
    </div>
  );
}

export function OrgTree({ snapshot, act }: { snapshot: Snapshot; act: Act }) {
  const { nodes } = snapshot.tree;
  const roots = nodes.filter((node) => node.parent === null);
  return (
    <section className="panel" data-panel="organization" aria-labelledby="org-heading">
      <h2 id="org-heading" className="panel-title">
        Organization key tree
      </h2>
      <p className="muted small">
        Your visible slice is what KeyQuorum&rsquo;s <code>visible_labels</code> returns for your label: lineage,
        siblings, descendants, and established-bridge peers.
        {snapshot.lastAccess
          ? ` Required and satisfied marks come from the last unlock of ${snapshot.lastAccess.fileName}.`
          : ""}
      </p>
      <p className="muted small">
        Each leaf&rsquo;s <strong>Revoke key</strong> button runs the real <code>keyquorum revoke</code>: it bans that
        hardware key from future trees and drops its existing bindings and pairings. It does not evict the leaf or
        refresh survivor shares — that still takes collecting the survivors&rsquo; keys, which stays a Terminal-tab
        job. <strong>Reissue</strong> replaces a leaf&rsquo;s hardware key outright onto an already-provisioned token
        (<code>keyquorum reissue --as {RESTRUCTURE_AUTHORITY}</code>); the CLI refuses leaves outside{" "}
        {RESTRUCTURE_AUTHORITY}&rsquo;s subtree.
      </p>
      <ul className="tree">
        {roots.map((node) => (
          <Node key={node.label} node={node} nodes={nodes} act={act} snapshot={snapshot} />
        ))}
      </ul>
      <Connections snapshot={snapshot} act={act} />
      <RestructureAdmin snapshot={snapshot} act={act} />
    </section>
  );
}
