import { useEffect, useRef, useState } from "react";

export function Terminal({ cwd, lines, onRun }: { cwd: string; lines: string[]; onRun: (line: string) => void }) {
  const [input, setInput] = useState("");
  const outputRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    const node = outputRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [lines]);
  return (
    <section className="panel panel-wide" data-panel="terminal" aria-labelledby="terminal-heading">
      <h2 id="terminal-heading" className="panel-title">
        Advanced: terminal
      </h2>
      <p className="small muted">
        A shell on the same lab machine the buttons use; they run these same commands. Try{" "}
        <code>keyquorum-device list /media/alice-usb</code>, <code>bridge list 1</code>,{" "}
        <code>usb insert david</code>, or <code>su david</code>.
      </p>
      <pre className="terminal-output" ref={outputRef} aria-live="polite" data-testid="terminal-output">
        {lines.join("\n")}
      </pre>
      <form
        className="terminal-input"
        onSubmit={(event) => {
          event.preventDefault();
          const line = input.trim();
          if (!line) return;
          onRun(line);
          setInput("");
        }}
      >
        <label htmlFor="terminal-line" className="visually-hidden">
          Terminal command
        </label>
        <span aria-hidden="true">{cwd}$</span>
        <input
          id="terminal-line"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <button type="submit" className="btn">
          Run
        </button>
      </form>
    </section>
  );
}
