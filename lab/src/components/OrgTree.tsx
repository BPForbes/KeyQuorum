import { useId, useState } from "react";
import type { Act } from "../App";
import type { Snapshot, TreeNodeView } from "../api/types";

function Node({ node, nodes, act }: { node: TreeNodeView; nodes: TreeNodeView[]; act: Act }) {
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
          <button
            type="button"
            className="btn small-btn"
            onClick={() => act((client) => client.revokeKey(node.label))}
            aria-label={`Revoke ${node.label}'s hardware key`}
          >
            Revoke key
          </button>
        ) : null}
      </div>
      {children.length > 0 ? (
        <ul>
          {children.map((child) => (
            <Node key={child.label} node={child} nodes={nodes} act={act} />
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
        job.
      </p>
      <ul className="tree">
        {roots.map((node) => (
          <Node key={node.label} node={node} nodes={nodes} act={act} />
        ))}
      </ul>
      <Connections snapshot={snapshot} act={act} />
    </section>
  );
}
