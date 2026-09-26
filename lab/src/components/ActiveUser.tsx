import type { Snapshot } from "../api/types";

export function ActiveUser({ snapshot, onSwitch }: { snapshot: Snapshot; onSwitch: (id: string) => void }) {
  const user = snapshot.activeUser;
  const drive = snapshot.drives.find((candidate) => candidate.id === user.driveId);
  return (
    <section className="panel active-user" aria-labelledby="active-user-heading">
      <div className="active-user-who">
        <h2 id="active-user-heading" className="panel-title">
          Active user
        </h2>
        <p className="active-user-name">
          <strong data-testid="active-user-name">{user.name}</strong> <code data-testid="active-user-label">{user.label}</code>
        </p>
        <p className="muted">{user.role}</p>
        <p className="muted">
          Key slot on {drive?.name ?? "no drive"}:{" "}
          <span className={drive?.connected ? "state-ok" : "state-off"}>
            {drive?.connected ? "inserted" : "not inserted"}
          </span>
        </p>
      </div>
      <div className="user-switch" role="group" aria-label="Switch user">
        {snapshot.users.map((candidate) => (
          <button
            key={candidate.id}
            type="button"
            className="chip"
            aria-pressed={candidate.active}
            onClick={() => onSwitch(candidate.id)}
          >
            <span>{candidate.name}</span> <code>{candidate.label}</code>
          </button>
        ))}
      </div>
    </section>
  );
}
