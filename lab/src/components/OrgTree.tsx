import type { Snapshot, TreeNodeView } from "../api/types";

function Node({ node, nodes }: { node: TreeNodeView; nodes: TreeNodeView[] }) {
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

export function OrgTree({ snapshot }: { snapshot: Snapshot }) {
  const { nodes, bridges } = snapshot.tree;
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
      <ul className="tree">
        {roots.map((node) => (
          <Node key={node.label} node={node} nodes={nodes} />
        ))}
      </ul>
      {bridges.length > 0 ? (
        <p className="small">
          Established bridge{bridges.length > 1 ? "s" : ""}:{" "}
          {bridges.map(([a, b]) => (
            <code key={`${a}-${b}`}>
              {a} ↔ {b}
            </code>
          ))}
        </p>
      ) : null}
    </section>
  );
}
