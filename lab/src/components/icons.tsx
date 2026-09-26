// Minimal inline icons for the Explorer. Kept tiny and dependency-free
// rather than pulling in an icon font just for this panel.

export function FolderIcon() {
  return (
    <svg viewBox="0 0 20 16" width="18" height="16" aria-hidden="true" focusable="false">
      <path
        d="M1 2.5C1 1.7 1.7 1 2.5 1H7l2 2h8.5c.8 0 1.5.7 1.5 1.5v9c0 .8-.7 1.5-1.5 1.5h-15C1.7 15 1 14.3 1 13.5v-11Z"
        fill="var(--action)"
        opacity="0.85"
      />
    </svg>
  );
}

export function FileIcon({ expired }: { expired?: boolean }) {
  return (
    <svg viewBox="0 0 16 18" width="14" height="16" aria-hidden="true" focusable="false">
      <path
        d="M2 1.5C2 .7 2.7 0 3.5 0H9l5 5v11.5c0 .8-.7 1.5-1.5 1.5h-9C2.7 18 2 17.3 2 16.5v-15Z"
        fill={expired ? "var(--error)" : "var(--text-subtle)"}
        opacity="0.75"
      />
      <path d="M9 0v4.5c0 .3.2.5.5.5H14L9 0Z" fill="var(--surface-raised)" opacity="0.9" />
    </svg>
  );
}

export function DriveIcon({ connected }: { connected: boolean }) {
  return (
    <svg viewBox="0 0 20 14" width="18" height="13" aria-hidden="true" focusable="false">
      <rect
        x="1"
        y="3"
        width="18"
        height="9"
        rx="2"
        fill={connected ? "var(--ok)" : "var(--text-subtle)"}
        opacity={connected ? 0.85 : 0.5}
      />
      <rect x="4" y="6" width="3" height="3" rx="0.5" fill="var(--p-ink)" opacity="0.5" />
    </svg>
  );
}
