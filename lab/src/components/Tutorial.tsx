// A gated, self-paced walkthrough of the lab's own controls: pick a
// module, and each step spotlights the part of the page it's about. A step
// with a real action to try (isDone defined) waits for that action to
// actually happen — checked against the live snapshot and the latest
// activity-log entry — rather than just advancing on a click. A step with
// no action to check just explains something and advances on demand.
import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { Act, Tab } from "../App";
import type { Snapshot } from "../api/types";
import { TUTORIALS, type TutorialMemory, type TutorialModule } from "../tutorial/modules";
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

/** Keeps `value` within [min, max], anchoring to `min` when the box is too big to fit at all. */
export function Tutorial({
  pickerOpen,
  onPickerClose,
  snapshot,
  tab,
  setTab,
  act,
}: {
  pickerOpen: boolean;
  onPickerClose: () => void;
  snapshot: Snapshot;
  tab: Tab;
  setTab: (tab: Tab) => void;
  act: Act;
}) {
  const [progress, setProgress] = useState<{ moduleId: string; stepIndex: number } | null>(null);
  const [finishedModule, setFinishedModule] = useState<TutorialModule | null>(null);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const [stepDone, setStepDone] = useState(false);
  // The step card is docked in a corner, not placed beside its target, so it
  // never covers the part of the page it is teaching.
  const scrolledRef = useRef(false);
  const [minimized, setMinimized] = useState(false);
  const [side, setSide] = useState<"right" | "left">("right");

  const snapshotRef = useRef(snapshot);
  snapshotRef.current = snapshot;
  const actRef = useRef(act);
  actRef.current = act;
  const advanceTimerRef = useRef<number | null>(null);
  // The activity-log seq at the moment the current step began: isDone is
  // only ever evaluated once a *newer* entry appears, so a condition left
  // over from before this step started (or before the module was opened)
  // can't satisfy it by itself.
  const stepStartSeqRef = useRef<number>(-1);
  // Data one step's `remember` captured, for a later step in the same
  // module to read back via its own `isDone`. Reset when a module starts.
  const memoryRef = useRef<TutorialMemory>({});
  const headingRef = useRef<HTMLHeadingElement>(null);

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
    memoryRef.current = {};
    setFinishedModule(null);
    setProgress({ moduleId: id, stepIndex: 0 });
    onPickerClose();
  };

  // A new step: reset its "done" state, switch tabs if it names one
  // (matters at phone width, where only the active tab's panel is
  // visible), record the activity cursor this step starts from, and let
  // the next poll re-measure from a clean slate.
  useEffect(() => {
    clearAdvanceTimer();
    setStepDone(false);
    setRect(null);
    scrolledRef.current = false;
    // ensure runs a real action (e.g. switch away from a blocked identity)
    // before the cursor is captured, so that corrective action can never
    // itself be mistaken for the visitor's own -- and the step's precise
    // starting point (already-there vs. blocked) is settled every time it
    // is entered, including by clicking Back into it.
    const effective = step?.ensure ? step.ensure(snapshotRef.current, actRef.current) : snapshotRef.current;
    stepStartSeqRef.current = effective.activity[0]?.seq ?? -1;
    if (step?.tab && step.tab !== tab) setTab(step.tab);
    headingRef.current?.focus();
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
      let nextRect = target ? target.getBoundingClientRect() : null;
      // Bring an off-screen target into view once per step, so the card can
      // stay in its corner and the spotlight still shows the target.
      if (target && nextRect && !scrolledRef.current) {
        scrolledRef.current = true;
        if (nextRect.bottom < 0 || nextRect.top > window.innerHeight) {
          target.scrollIntoView({ block: "center" });
          nextRect = target.getBoundingClientRect();
        }
      }
      setRect((previous) => (sameRect(previous, nextRect) ? previous : nextRect));
      if (step.isDone && !stepDone) {
        const latest = currentSnapshot.activity[0];
        const isFresh = (latest?.seq ?? -1) > stepStartSeqRef.current;
        const kindMatches = !step.requiredKind || latest?.kind === step.requiredKind;
        if (isFresh && kindMatches && step.isDone(currentSnapshot, latest, memoryRef.current)) {
          if (step.remember) {
            memoryRef.current = { ...memoryRef.current, ...step.remember(currentSnapshot, latest) };
          }
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
    const categories = [
      ["identities", "Identities & drives", "People, keys, organization policy, and physical custody."],
      ["files", "Files & unlocking", "Protection schemes, access decisions, portability, and evidence."],
      ["mailbox", "Mailbox: sending & receiving", "Delivery decisions and the protocols carried by sealed letters."],
      ["history", "File history", "Tracked files: revisions, trust, hand-offs, merges, and expiry."],
    ] as const;
    return (
      <Modal title="Tutorials & Documentation" onClose={onPickerClose} labelledBy="tutorial-picker-heading">
        <p className="small muted">
          Short, self-contained walkthroughs of one part of the lab. Pick whichever covers what you want to learn —
          you don&rsquo;t need to do them in order, or do all of them.
        </p>
        {/*
          lab/public/docs/*.pdf are compiled artifacts checked into the
          repo (Vite copies public/ verbatim into dist/), not generated by
          this build. Regenerate both with a two-pass `pdflatex -output-
          directory=... docs/KeyQuorum_Manual.tex` / `...Lab_Manual.tex`
          from the repo root after editing anything under docs/, and copy
          the results back into this directory.
        */}
        <section className="tutorial-category" aria-labelledby="tutorial-docs-heading">
          <h3 id="tutorial-docs-heading">Documentation</h3>
          <p className="small muted">
            The full manuals, as PDFs: the CLI this lab runs underneath its interface, and the lab&rsquo;s own GUI.
          </p>
          <ul className="tutorial-picker-list">
            <li className="tutorial-picker-item">
              <a href={`${import.meta.env.BASE_URL}docs/KeyQuorum_Manual.pdf`} target="_blank" rel="noopener noreferrer">
                KeyQuorum (CLI)
              </a>
            </li>
            <li className="tutorial-picker-item">
              <a
                href={`${import.meta.env.BASE_URL}docs/KeyQuorum_Lab_Manual.pdf`}
                target="_blank"
                rel="noopener noreferrer"
              >
                KeyQuorum Lab (this GUI)
              </a>
            </li>
          </ul>
        </section>
        {categories.map(([id, title, summary]) => (
          <section key={id} className="tutorial-category" aria-labelledby={`tutorial-category-${id}`}>
            <h3 id={`tutorial-category-${id}`}>{title}</h3>
            <p className="small muted">{summary}</p>
            <ul className="tutorial-picker-list">
              {TUTORIALS.filter((candidate) => candidate.category === id).map((candidate) => (
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
          </section>
        ))}
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

  return (
    // Non-modal: a gated step requires operating a control elsewhere on the
    // page, so outside content must stay reachable to assistive tech too.
    <div className="tutorial-overlay" role="dialog" aria-labelledby="tutorial-step-heading">
      <div className="tutorial-spotlight" style={spotlightStyle} />
      <div
        className={`tutorial-tooltip is-docked-${side}`}
        data-testid="tutorial-card"
      >
        <p className="tutorial-progress">
          {module.title} · step {progress.stepIndex + 1} of {module.steps.length}
        </p>
        <h3 id="tutorial-step-heading" ref={headingRef} tabIndex={-1}>
          {step.title}
        </h3>
        {minimized ? null : <div className="tutorial-body">{step.body}</div>}
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
          <button type="button" className="btn small-btn" onClick={() => setMinimized(!minimized)}>
            {minimized ? "Show text" : "Hide text"}
          </button>
          <button
            type="button"
            className="btn small-btn"
            onClick={() => setSide(side === "right" ? "left" : "right")}
            aria-label={`Move this card to the ${side === "right" ? "left" : "right"}`}
          >
            {side === "right" ? "← Move" : "Move →"}
          </button>
          <button type="button" className="btn small-btn" onClick={exit}>
            Exit tutorial
          </button>
        </div>
      </div>
    </div>
  );
}
