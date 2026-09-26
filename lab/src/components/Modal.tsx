import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

export function Modal({
  title,
  onClose,
  children,
  labelledBy,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  labelledBy: string;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  // Callers pass a fresh inline onClose on every render, and App re-renders
  // every 3s; keying the effect on it would yank focus back to Close.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCloseRef.current();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={labelledBy}>
        <div className="modal-titlebar">
          <h3 id={labelledBy}>{title}</h3>
          <button type="button" className="modal-close" onClick={onClose} ref={closeRef} aria-label="Close">
            ×
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
