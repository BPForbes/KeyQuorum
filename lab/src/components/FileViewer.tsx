import { useState } from "react";
import type { ActionResult } from "../api/types";
import { Trace } from "./ActivityPanel";
import { Modal } from "./Modal";

export function FileViewer({ result, fileName, onClose }: { result: ActionResult; fileName: string; onClose: () => void }) {
  const [showTrace, setShowTrace] = useState(!result.ok);
  return (
    <Modal title={fileName} onClose={onClose} labelledBy="viewer-title">
      {result.opened ? (
        <pre className="viewer-content" data-testid="opened-file">
          {result.opened.text}
        </pre>
      ) : (
        <div className="viewer-denied" role="alert">
          <p className="viewer-denied-title">{result.message}</p>
          <p className="small muted">
            {fileName} could not be opened. This mirrors a real access denial or an expired file being removed —
            nothing was faked to get here.
          </p>
        </div>
      )}
      <button
        type="button"
        className="btn small-btn"
        aria-expanded={showTrace}
        onClick={() => setShowTrace((value) => !value)}
      >
        {showTrace ? "Hide" : "Show"} the access trace
      </button>
      {showTrace ? <Trace steps={result.trace} /> : null}
    </Modal>
  );
}
