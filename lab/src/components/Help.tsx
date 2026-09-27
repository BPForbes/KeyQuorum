// Static in-app documentation. Unlike the other panels, Help takes no
// snapshot or act — it never runs a command, it only explains what the
// other panels do and how they map onto the real keyquorum /
// keyquorum-device CLI, so that a first-time visitor to the lab does not
// have to leave the page (or read source) to find their footing.

export function Help() {
  return (
    <section className="panel panel-wide" data-panel="help" aria-labelledby="help-heading">
      <h2 id="help-heading" className="panel-title">
        Help: using this lab
      </h2>

      <p className="small muted">
        Everything below describes what is actually on this page right now. Every button here runs a real{" "}
        <code>keyquorum</code> or <code>keyquorum-device</code> command against the in-browser machine; the Activity
        tab shows the exact command line for whatever you last did, and the Terminal tab lets you type the same
        commands yourself. There is no separate &ldquo;demo mode&rdquo; behind the buttons.
      </p>

      <h3>Before you start: who you are, and what &ldquo;inserted&rdquo; means</h3>
      <p className="small muted">
        The bar at the top of the page (<strong>Active user</strong>) shows who you are acting as right now, and
        which USB drive their personal key slot lives on. Click another name&rsquo;s chip to switch to them, the way
        sitting down at a different desk would. Most actions need that person&rsquo;s drive <em>inserted</em> first
        &mdash; a mock USB drive behaves like a real one: its slots are only usable while it is connected, and a slot
        moved onto someone else&rsquo;s drive needs both drives inserted at once, just as moving a physical token
        between two real drives would.
      </p>

      <h3>Organization key tree</h3>
      <p className="small muted">
        The org-wide split tree, drawn as the dotted-label hierarchy it is (<code>M</code>, <code>M.S</code>,{" "}
        <code>M.S.1</code>, &hellip;). You only ever see your own slice &mdash; your lineage, your descendants,
        siblings, and established-bridge peers &mdash; the same slice{" "}
        <code>keyquorum tree fetch</code> would return for your label. A leaf tagged <em>required</em> contributed a
        share the last time you unlocked a file; <em>satisfied</em> means that share was actually presented.
        <strong> Revoke key</strong> bans a leaf&rsquo;s hardware key outright (<code>keyquorum revoke</code>);{" "}
        <strong>Reissue&hellip;</strong> replaces it with an already-provisioned replacement token. Further down,{" "}
        <strong>Bridges</strong> whitelists and establishes cross-branch links (<code>bridge allow</code> /{" "}
        <code>bridge add</code>), and <strong>Tree restructure</strong> walks through proposing a new public
        generation and collecting the parent&rsquo;s countersignature when one is required.
      </p>

      <h3>Mock USB devices</h3>
      <p className="small muted">
        Each card is one container: a signed device descriptor plus one sealed token per slot. Use{" "}
        <strong>Insert</strong> / <strong>Eject</strong> to plug a drive in or pull it out. <strong>Move</strong> asks
        for a destination drive (both drives must be inserted) and relocates a slot&rsquo;s keypair onto it &mdash;
        this is the point where two people&rsquo;s tokens land in one physical container and start counting as a
        single device toward any multi-device quorum. <strong>Copy</strong> instead leaves the original slot active
        and seals a second copy elsewhere, using the same passphrase that already unlocks it.
      </p>

      <h3>File Explorer</h3>
      <p className="small muted">
        A Windows-Explorer-style view onto the active user&rsquo;s files, grouped into folders. Double-click a file
        (or select it and press <strong>Open</strong>) to unlock and view it &mdash; a quorum file prompts for the
        shares it needs, a password file for its password. <strong>Send&hellip;</strong> seals a copy to another
        label&rsquo;s key and drops it in their inbox; <strong>Sign</strong> is only offered on public or received
        plaintext; <strong>Properties</strong> shows the file&rsquo;s protection, size, and timestamps. Right-click a
        row for the same actions. A file with an expiry stamp shows a status pill that flips to <em>expired</em>{" "}
        on its own while the tab is open &mdash; the next unlock attempt (or a background scan) then deletes it for
        real, the same destructive purge the CLI performs.
      </p>

      <h3>Inbox and sent</h3>
      <p className="small muted">
        Letters are sealed to a recipient&rsquo;s key and routed by the mailbox relay without it ever reading them
        &mdash; sender and contents stay hidden until <strong>Receive</strong> unseals a letter with your own slot
        (<code>keyquorum deliver open</code>). <strong>Reject</strong> answers with a signed refusal instead. The
        Sent view tracks whether a delivery is still awaiting the recipient&rsquo;s signed acknowledgement, and{" "}
        <strong>Check relay for acknowledgements</strong> pulls any that are waiting.
      </p>

      <h3>Security &amp; devices</h3>
      <p className="small muted">
        Everything that is not the hardware-key quorum tree or a file. Lock a note with a password (and optionally a
        PIN); export a file or credential as a portable sealed bundle; mint a time-limited share link; provision a
        fresh slot on an inserted drive and register it as a new leaf; sign or verify with a private sign bridge you
        belong to; and, at the bottom, read-only device logs and relay counters for the in-process mailbox this lab
        runs against.
      </p>

      <h3>Activity and access trace</h3>
      <p className="small muted">
        Every action you take leaves a trace here: which checks ran, in order, and whether each one passed. The{" "}
        <strong>Equivalent operation</strong> line under the latest trace is the literal command line that action
        ran &mdash; the same one you could type in the Terminal tab. The full log below keeps every action for the
        session, not just the last one.
      </p>

      <h3>Terminal</h3>
      <p className="small muted">
        A real shell on this same lab machine. Every button on every other tab runs a command here under the hood;
        typing it directly works identically, including commands no button exposes yet. A few starting points:{" "}
        <code>keyquorum-device list /media/alice-usb</code>, <code>bridge list 1</code>,{" "}
        <code>usb insert david</code>, and <code>su david</code> to switch identity from the shell instead of the
        Active user bar.
      </p>

      <h3>Where the concepts are documented</h3>
      <p className="small muted">
        This page explains the controls; it does not re-explain the security model behind them. For the full{" "}
        <code>keyquorum</code> / <code>keyquorum-device</code> command reference and the reasoning behind hardware
        custody, threshold quorum trees, private sign bridges, authenticated updates, and the hierarchical-principal
        model that ties them together, see the KeyQuorum manual in the project repository (<code>docs/</code>) or the
        top-level <code>README.md</code>:{" "}
        <a href="https://github.com/BPForbes/KeyQuorum#readme" target="_blank" rel="noreferrer">
          github.com/BPForbes/KeyQuorum
        </a>
        .
      </p>
    </section>
  );
}
