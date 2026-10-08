// Cleanup that must run when the current view goes away: the router calls
// `disposeAll` before it draws another view and on `pagehide`. A panel that
// holds something secret (the provisioning panels' private keys) registers
// its own cleanup with `onDispose`. Each cleanup runs once; one that throws
// does not stop the others.

const pending = [];

// Registers `fn` to run when the current view is disposed.
export function onDispose(fn) {
  pending.push(fn);
}

// Wires the page's lifecycle: leaving the page disposes the current view, and
// a page the browser restores from its back/forward cache (whose panels were
// disposed on the way out) draws its view again with `render`, so the panels
// work instead of wiping every new result.
export function watchPageLifecycle(win, render) {
  win.addEventListener("pagehide", disposeAll);
  win.addEventListener("pageshow", (event) => {
    if (event.persisted) void render();
  });
}

// Runs and forgets every registered cleanup.
export function disposeAll() {
  for (const fn of pending.splice(0)) {
    try {
      fn();
    } catch {
      // a failed cleanup must not keep the next view from drawing
    }
  }
}
