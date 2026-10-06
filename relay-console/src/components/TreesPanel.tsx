import { useState } from "react";
import type { Act } from "../App";
import type { PublicNode, PublicTree, Session } from "../api/types";

function Node({ node, nodes }: { node: PublicNode; nodes: PublicNode[] }) {
  const children = nodes.filter((candidate) => candidate.parent_label === node.label);
  const split = node.threshold !== null;
  return (
    <li>
      <div className="tree-node" data-testid={`tree-node-${node.label}`} data-active={node.is_active || undefined}>
        <span className="tree-label">
          <code>{node.label}</code>
        </span>
        <span className="tree-tags">
          <span className="tag">{split ? `split · ${node.threshold} of ${children.length}` : "leaf"}</span>
          <span className="tag">{node.is_active ? "active" : "inactive"}</span>
          {node.encryption_fingerprint ? <span className="tag">recipient {node.encryption_fingerprint.slice(0, 12)}…</span> : null}
        </span>
      </div>
      {children.length > 0 ? (
        <ul>
          {children.map((child) => (
            <Node key={child.label} node={child} nodes={nodes} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** `GET /trees/{label}/context`: the public topology slice the signed-in
 * `inbox.pull` key's recipient may see. Public structure only; the relay
 * holds no share and no private key, so there is nothing more to show. */
export function TreesPanel({ session, act }: { session: Session | null; act: Act }) {
  const [label, setLabel] = useState("");
  const [tree, setTree] = useState<PublicTree | null>(null);
  const pull = session?.scope === "inbox.pull";
  const roots = tree ? tree.nodes.filter((node) => node.parent_label === null || !tree.nodes.some((n) => n.label === node.parent_label)) : [];
  return (
    <section className="panel" data-panel="trees" aria-labelledby="trees-heading">
      <h2 id="trees-heading" className="panel-title">
        Public trees
      </h2>
      <p className="small muted">
        The canonical public split-tree the relay stores for a label, sliced to what the signed-in key's recipient may
        see. The relay answers this only to an <code>inbox.pull</code> key bound to a recipient; an admin key is
        refused (403), so sign in as the customer's pull key to see their view.
      </p>
      {!session ? (
        <p className="empty">Sign in with an <code>inbox.pull</code> key.</p>
      ) : !pull ? (
        <p className="empty">
          This key's scope is <code>{session.scope}</code>; the relay needs <code>inbox.pull</code> here.
        </p>
      ) : (
        <form
          className="lookup-form"
          onSubmit={(event) => {
            event.preventDefault();
            const wanted = label.trim();
            if (!wanted) return;
            void act(`Tree ${wanted} fetched`, (relay) => relay.treeContext(wanted)).then((answer) => setTree(answer));
          }}
        >
          <label htmlFor="tree-label">Tree label</label>
          <input id="tree-label" data-testid="tree-label" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="M.S" />
          <button type="submit" className="btn">
            Fetch slice
          </button>
        </form>
      )}
      {tree ? (
        <div data-testid="tree-view">
          <p className="small">
            <strong>{tree.label}</strong> · generation {tree.generation} · {tree.nodes.length} visible node
            {tree.nodes.length === 1 ? "" : "s"} · {tree.links.length} link{tree.links.length === 1 ? "" : "s"} ·{" "}
            {tree.whitelist.length} whitelisted edge{tree.whitelist.length === 1 ? "" : "s"}
          </p>
          <ul className="tree">
            {roots.map((root) => (
              <Node key={root.label} node={root} nodes={tree.nodes} />
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
