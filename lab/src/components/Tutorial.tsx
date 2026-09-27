// A gated, self-paced walkthrough of the lab's own controls: pick a
// module, and each step spotlights the part of the page it's about. A step
// with a real action to try (isDone defined) waits for that action to
// actually happen — checked against the live snapshot and the latest
// activity-log entry — rather than just advancing on a click. A step with
// no action to check just explains something and advances on demand.
import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { Tab } from "../App";
import type { Snapshot } from "../api/types";
import { TUTORIALS, type TutorialModule } from "../tutorial/modules";
import { Modal } from "./Modal";

const POLL_MS = 350;
const ADVANCE_DELAY_MS = 900;

function resolveTarget(candidates: (string | null)[]): HTMLElement | null {
  for (const selector of candidates) {
    if (!selector) continue;
    const element = document.querySelector<HTMLElement>(selector);
    if (element) {
      const rect = element.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) return element;
    }
  }
  return null;
}

function sameRect(a: DOMRect | null, b: DOMRect | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.top === b.top && a.left === b.left && a.width === b.width && a.height === b.height;
}

export function Tutorial({
  pickerOpen,
  onPickerClose,
  snapshot,
  tab,
  setTab,
}: {
  pickerOpen: boolean;
  onPickerClose: () => void;
  snapshot: Snapshot;
  tab: Tab;
  setTab: (tab: Tab) => void;
}) {
  const [progress, setProgress] = useState<{ moduleId: string; stepIndex: number } | null>(null);
  const [finishedModule, setFinishedModule] = useState<TutorialModule | null>(null);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const [stepDone, setStepDone] = useState(false);

  const snapshotRef = useRef(snapshot);
  snapshotRef.current = snapshot;
  const advanceTimerRef = useRef<number | null>(null);

  const module = progress ? TUTORIALS.find((candidate) => candidate.id === progress.moduleId) ?? null : null;
  const step = module && progress ? module.steps[progress.stepIndex] : null;

  const clearAdvanceTimer = () => {
    if (advanceTimerRef.current !== null) {
      window.clearTimeout(advanceTimerRef.current);
      advanceTimerRef.current = null;
    }
  };

  const advance = () => {
    clearAdvanceTimer();
    setProgress((previous) => {
      if (!previous) return previous;
      const current = TUTORIALS.find((candidate) => candidate.id === previous.moduleId);
      if (!current) return null;
      if (previous.stepIndex + 1 >= current.steps.length) {
        setFinishedModule(current);
        return null;
      }
      return { moduleId: previous.moduleId, stepIndex: previous.stepIndex + 1 };
    });
  };

  const back = () => {
    clearAdvanceTimer();
    setProgress((previous) => (previous ? { ...previous, stepIndex: Math.max(0, previous.stepIndex - 1) } : previous));
  };

  const exit = () => {
    clearAdvanceTimer();
    setProgress(null);
  };

  const start = (id: string) => {
    setFinishedModule(null);
    setProgress({ moduleId: id, stepIndex: 0 });
    onPickerClose();
  };

  // A new step: reset its "done" state, switch tabs if it names one
  // (matters at phone width, where only the active tab's panel is
  // visible), and let the next poll re-measure from a clean slate.
  useEffect(() => {
    clearAdvanceTimer();
    setStepDone(false);
    setRect(null);
    if (step?.tab && step.tab !== tab) setTab(step.tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [progress?.moduleId, progress?.stepIndex]);

  // Poll rather than react only to snapshot changes: opening a folder in
  // the File Explorer, for instance, is local UI state with no snapshot of
  // its own, so a step's target can flip (folder tile -> file row) between
  // snapshot updates.
  useEffect(() => {
    if (!step) return;
    const tick = () => {
      const currentSnapshot = snapshotRef.current;
      const target = resolveTarget(step.target(currentSnapshot));
      const nextRect = target ? target.getBoundingClientRect() : null;
      setRect((previous) => (sameRect(previous, nextRect) ? previous : nextRect));
      if (step.isDone && !stepDone) {
        const latest = currentSnapshot.activity[0];
        if (step.isDone(currentSnapshot, latest)) {
          setStepDone(true);
          clearAdvanceTimer();
          advanceTimerRef.current = window.setTimeout(advance, ADVANCE_DELAY_MS);
        }
      }
    };
    tick();
    const id = window.setInterval(tick, POLL_MS);
    window.addEventListener("resize", tick);
    window.addEventListener("scroll", tick, true);
    return () => {
      window.clearInterval(id);
      window.removeEventListener("resize", tick);
      window.removeEventListener("scroll", tick, true);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, stepDone]);

  useEffect(() => clearAdvanceTimer, []);

  if (pickerOpen && !module) {
    return (
      <Modal title="Guided tutorials" onClose={onPickerClose} labelledBy="tutorial-picker-heading">
        <p className="small muted">
          Short, self-contained walkthroughs of one part of the lab. Pick whichever covers what you want to learn —
          you don&rsquo;t need to do them in order, or do all of them.
        </p>
        <ul className="tutorial-picker-list">
          {TUTORIALS.map((candidate) => (
            <li key={candidate.id} className="tutorial-picker-item">
              <div>
                <strong>{candidate.title}</strong>
                <p className="small muted">{candidate.summary}</p>
              </div>
              <button type="button" className="btn btn-primary" onClick={() => start(candidate.id)}>
                Start
              </button>
            </li>
          ))}
        </ul>
      </Modal>
    );
  }

  if (finishedModule) {
    return (
      <Modal title="Module complete" onClose={() => setFinishedModule(null)} labelledBy="tutorial-finished-heading">
        <p>
          You finished <strong>{finishedModule.title}</strong>. Open another module any time from the{" "}
          <strong>Tutorials</strong> button.
        </p>
        <div className="button-row">
          <button
            type="button"
            className="btn"
            onClick={() => {
              setFinishedModule(null);
              onPickerClose();
            }}
          >
            Close
          </button>
        </div>
      </Modal>
    );
  }

  if (!module || !step || !progress) return null;

  const isLast = progress.stepIndex === module.steps.length - 1;
  const pad = 8;
  const spotlightStyle: CSSProperties = rect
    ? {
        top: rect.top - pad,
        left: rect.left - pad,
        width: rect.width + pad * 2,
        height: rect.height + pad * 2,
      }
    : { top: "45%", left: "50%", width: 0, height: 0 };

  const tooltipTop = rect ? Math.min(rect.bottom + 16, window.innerHeight - 220) : undefined;
  const tooltipLeft = rect ? Math.min(Math.max(rect.left, 16), window.innerWidth - 336) : undefined;

  return (
    <div className="tutorial-overlay" role="dialog" aria-modal="true" aria-labelledby="tutorial-step-heading">
      <div className="tutorial-spotlight" style={spotlightStyle} />
      <div
        className="tutorial-tooltip"
        style={rect ? { top: tooltipTop, left: tooltipLeft } : { top: "50%", left: "50%", transform: "translate(-50%, -50%)" }}
      >
        <p className="tutorial-progress">
          {module.title} · step {progress.stepIndex + 1} of {module.steps.length}
        </p>
        <h3 id="tutorial-step-heading">{step.title}</h3>
        <div className="tutorial-body">{step.body}</div>
        {step.isDone ? (
          <p className={`tutorial-gate ${stepDone ? "is-done" : ""}`} role="status">
            {stepDone ? "✓ Nice — that's it." : "Waiting for you to try it…"}
          </p>
        ) : null}
        {!rect ? (
          <p className="small muted">Looking for that part of the page — check you're on the right tab.</p>
        ) : null}
        <div className="tutorial-actions">
          <button type="button" className="btn small-btn" onClick={back} disabled={progress.stepIndex === 0}>
            Back
          </button>
          {step.isDone && !stepDone ? (
            <button type="button" className="btn small-btn" onClick={advance}>
              Skip this step
            </button>
          ) : (
            <button type="button" className="btn btn-primary small-btn" onClick={advance}>
              {isLast ? "Finish" : "Next"}
            </button>
          )}
          <button type="button" className="btn small-btn" onClick={exit}>
            Exit tutorial
          </button>
        </div>
      </div>
    </div>
  );
}
