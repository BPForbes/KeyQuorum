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
