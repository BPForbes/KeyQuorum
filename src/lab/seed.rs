//! Synthetic seed data for the browser lab. Every name, label, passphrase,
//! and file body here is invented for the demonstration and is public by
//! construction: it ships inside the WASM bundle.

use crate::device::{CustodyMode, UnlockApproval};

pub struct UserSeed {
    pub id: &'static str,
    pub name: &'static str,
    pub label: &'static str,
    pub role: &'static str,
    /// Their personal drive at seed time. Slots can be moved to any other
    /// drive afterward (`LabState::move_slot`), so this is a starting
    /// point, not a fixed assignment.
    pub drive: &'static str,
}

pub struct DriveSeed {
    pub id: &'static str,
    pub name: &'static str,
    pub mount: &'static str,
    /// Slot labels provisioned on this drive at seed time.
    pub slots: &'static [&'static str],
    pub inserted: bool,
}

/// When a quorum-protected file's TTL falls, relative to the moment the
/// lab seeds itself. Resolved to a concrete UTC timestamp with a SQLite
/// `datetime('now', modifier)` call so "expires soon" files really do
/// expire while the tab is open.
pub enum Expiry {
    Never,
    /// A SQLite datetime modifier, e.g. `"-1 day"` (already expired at
    /// load) or `"+90 seconds"` (expires shortly after load).
    Offset(&'static str),
}

pub enum Protection {
    Public,
    Quorum {
        threshold: u8,
        leaves: &'static [&'static str],
        custody: CustodyMode,
        minimum_devices: u8,
        approval: UnlockApproval,
        expires: Expiry,
    },
    /// Like `Quorum`, but one extra leaf is provisioned, included in the
    /// split, and then evicted (`key_tree::evict_and_refresh`) before the
    /// lab hands control to the visitor — a real ghost, not a cosmetic
    /// one. `ghost_label` is that leaf; it is never a `UserSeed` and
    /// never gets a drive of its own.
    QuorumWithGhost {
        threshold: u8,
        leaves: &'static [&'static str],
        ghost_label: &'static str,
        custody: CustodyMode,
        minimum_devices: u8,
    },
}

pub struct FileSeed {
    pub id: &'static str,
    pub folder: &'static str,
    pub name: &'static str,
    /// Which KeyQuorum rule this file exists to show.
    pub lesson: &'static str,
    pub contents: &'static str,
    pub protection: Protection,
}

pub const INITIAL_USER: &str = "alice";

/// Tree label of the organization key whose topology drives visibility.
pub const ORG_TREE: &str = "org";

/// The one cross-department bridge in the seed org: engineering and
/// accounting managers may reach each other, so their reports' visible
/// slices include the other manager, but not that manager's reports.
pub const ORG_BRIDGE: (&str, &str) = ("M.S", "M.A");

/// A former engineer, evicted from `legacy-migration-notes.txt`'s tree
/// before the lab starts. Never a `UserSeed`, never has a drive: the
/// point is that a ghost has no way to present a share at all.
pub const GHOST_LABEL: &str = "Priya";
pub const GHOST_NAME: &str = "Priya";
pub const GHOST_ROLE: &str = "Former Software Engineer (left the company)";

pub const USERS: &[UserSeed] = &[
    UserSeed {
        id: "morgan",
        name: "Morgan",
        label: "M",
        role: "Executive",
        drive: "morgan",
    },
    UserSeed {
        id: "sarah",
        name: "Sarah",
        label: "M.S",
        role: "Software Manager",
        drive: "sarah",
    },
    UserSeed {
        id: "alice",
        name: "Alice",
        label: "M.S.1",
        role: "Software Engineer",
        drive: "alice",
    },
    UserSeed {
        id: "bob",
        name: "Bob",
        label: "M.S.2",
        role: "Software Engineer",
        drive: "bob",
    },
    UserSeed {
        id: "david",
        name: "David",
        label: "M.A",
        role: "Accounting Manager",
        drive: "david",
    },
    UserSeed {
        id: "emma",
        name: "Emma",
        label: "M.A.1",
        role: "Accountant",
        drive: "emma",
    },
    UserSeed {
        id: "chris",
        name: "Chris",
        label: "M.A.2",
        role: "Accountant",
        drive: "chris",
    },
];

/// One personal drive per person, plus one spare so a slot can be moved
/// somewhere without immediately landing on someone else's drive. Slots
/// can be relocated to any drive at runtime — this is only the start.
pub const DRIVES: &[DriveSeed] = &[
    DriveSeed {
        id: "morgan",
        name: "Morgan's USB",
        mount: "/media/morgan-usb",
        slots: &["M"],
        inserted: false,
    },
    DriveSeed {
        id: "sarah",
        name: "Sarah's USB",
        mount: "/media/sarah-usb",
        slots: &["M.S"],
        inserted: true,
    },
    DriveSeed {
        id: "alice",
        name: "Alice's USB",
        mount: "/media/alice-usb",
        slots: &["M.S.1"],
        inserted: true,
    },
    DriveSeed {
        id: "bob",
        name: "Bob's USB",
        mount: "/media/bob-usb",
        slots: &["M.S.2"],
        inserted: false,
    },
    DriveSeed {
        id: "david",
        name: "David's USB",
        mount: "/media/david-usb",
        slots: &["M.A"],
        inserted: false,
    },
    DriveSeed {
        id: "emma",
        name: "Emma's USB",
        mount: "/media/emma-usb",
        slots: &["M.A.1"],
        inserted: false,
    },
    DriveSeed {
        id: "chris",
        name: "Chris's USB",
        mount: "/media/chris-usb",
        slots: &["M.A.2"],
        inserted: false,
    },
    DriveSeed {
        id: "spare",
        name: "Spare USB",
        mount: "/media/spare-usb",
        slots: &[],
        inserted: false,
    },
];

pub const FILES: &[FileSeed] = &[
    // --- /public — no key tree at all ---
    FileSeed {
        id: "company-handbook",
        folder: "public",
        name: "company-handbook.txt",
        lesson: "No key tree: anyone can open it.",
        contents: "Example Co. handbook (synthetic)\n\nCore hours are 10:00-16:00.\nBadge in at the front desk.\nThis file is not protected by any key tree.\n",
        protection: Protection::Public,
    },
    FileSeed {
        id: "project-roadmap",
        folder: "public",
        name: "project-roadmap.md",
        lesson: "No key tree: a public document you can send to anyone in your slice.",
        contents: "# Roadmap (synthetic)\n\n- Q1: ship the widget API\n- Q2: migrate the build farm\n- Q3: retire the legacy dashboard\n",
        protection: Protection::Public,
    },
    FileSeed {
        id: "holiday-calendar",
        folder: "public",
        name: "holiday-calendar.csv",
        lesson: "No key tree: a public reference file.",
        contents: "date,holiday\n2026-01-01,New Year's Day\n2026-07-04,Independence Day\n2026-12-25,Christmas Day\n",
        protection: Protection::Public,
    },
    FileSeed {
        id: "brand-guidelines",
        folder: "public",
        name: "brand-guidelines.md",
        lesson: "No key tree: a public reference file.",
        contents: "# Brand guidelines (synthetic)\n\nPrimary color: #c98a4a\nWordmark: set in Fraunces, never stretched.\n",
        protection: Protection::Public,
    },
    // --- /engineering ---
    FileSeed {
        id: "architecture",
        folder: "engineering",
        name: "architecture.md",
        lesson: "Engineering access: any one engineering slot (1 of 3).",
        contents: "# Service architecture (synthetic)\n\nweb -> api -> queue -> workers -> store\nAll hostnames here are placeholders.\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.S", "M.S.1", "M.S.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "deployment-plan",
        folder: "engineering",
        name: "deployment-plan.txt",
        lesson: "2 of 3 engineering slots. Logical custody lets two slots on one USB meet the threshold, but they still count as one device.",
        contents: "Deployment plan (synthetic)\n1. Freeze main\n2. Canary 5%\n3. Promote if error budget holds\n",
        protection: Protection::Quorum {
            threshold: 2,
            leaves: &["M.S", "M.S.1", "M.S.2"],
            custody: CustodyMode::Logical,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "prod-credentials",
        folder: "engineering",
        name: "prod-credentials.txt",
        lesson: "An engineer's share is not enough: unlock_approval = parent, so M.S must sign.",
        contents: "Production credentials (synthetic placeholders)\nDB_USER=example_user\nDB_PASSWORD=not-a-real-password\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.S.1", "M.S.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::Parent,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "api-keys-rotation",
        folder: "engineering",
        name: "api-keys-rotation.log",
        lesson: "Already expired when the lab loaded: unlocking it deletes it for good, quorum or not.",
        contents: "2026-08-01 rotated staging key (synthetic)\n2026-08-15 rotated production key (synthetic)\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.S.1", "M.S.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Offset("-3 days"),
        },
    },
    FileSeed {
        id: "sprint-notes",
        folder: "engineering",
        name: "sprint-notes.md",
        lesson: "Expires shortly after the lab loads — watch its status change from Properties without touching anything else.",
        contents: "# Sprint notes (synthetic)\n\n- Reviewed the quorum lab\n- Fixed a flaky test\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.S.1", "M.S.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Offset("+90 seconds"),
        },
    },
    FileSeed {
        id: "legacy-migration-notes",
        folder: "engineering",
        name: "legacy-migration-notes.txt",
        lesson: "Originally 2 of 3 with Priya, a former engineer. Her share was evicted (key_tree::evict_and_refresh) when she left, and the survivors' shares were refreshed — now both remaining holders are required.",
        contents: "Legacy migration notes (synthetic)\nOwned jointly by the team; Priya wrote the original draft.\n",
        protection: Protection::QuorumWithGhost {
            threshold: 2,
            leaves: &["M.S.1", "M.S.2"],
            ghost_label: GHOST_LABEL,
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
        },
    },
    // --- /accounting ---
    FileSeed {
        id: "payroll",
        folder: "accounting",
        name: "payroll.csv",
        lesson: "Accounting quorum: 2 of 3 accounting slots.",
        contents: "employee,band,monthly\nexample-1,B2,0000\nexample-2,B3,0000\n(synthetic figures)\n",
        protection: Protection::Quorum {
            threshold: 2,
            leaves: &["M.A", "M.A.1", "M.A.2"],
            custody: CustodyMode::Logical,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "q3-budget",
        folder: "accounting",
        name: "q3-budget.csv",
        lesson: "Any one accounting slot (1 of 3).",
        contents: "line,amount\ncloud,1000\ntravel,250\n(synthetic figures)\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.A", "M.A.1", "M.A.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "vendor-contract-acme",
        folder: "accounting",
        name: "vendor-contract-acme.txt",
        lesson: "Already expired when the lab loaded.",
        contents: "Vendor contract: Acme Supplies (synthetic)\nTerm: 12 months. Renewal: automatic unless cancelled.\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.A.1", "M.A.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Offset("-12 hours"),
        },
    },
    FileSeed {
        id: "audit-checklist",
        folder: "accounting",
        name: "audit-checklist.md",
        lesson: "2 of 3 accounting slots. Expires shortly after the lab loads.",
        contents: "# Audit checklist (synthetic)\n\n- [ ] Reconcile Q3 ledger\n- [ ] Confirm vendor W-9s on file\n",
        protection: Protection::Quorum {
            threshold: 2,
            leaves: &["M.A", "M.A.1", "M.A.2"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Offset("+150 seconds"),
        },
    },
    FileSeed {
        id: "expense-report-q3",
        folder: "accounting",
        name: "expense-report-q3.csv",
        lesson: "Manager-only (M.A alone). Emma and Chris can see it in their slice through David but cannot open it themselves.",
        contents: "category,amount\ntravel,4200\nsoftware,1800\n(synthetic figures)\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M.A"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    // --- /executive ---
    FileSeed {
        id: "acquisition-plan",
        folder: "executive",
        name: "acquisition-plan.txt",
        lesson: "Cross-department: 2 of {M, M.S, M.A} on at least 2 physical devices.",
        contents: "Acquisition plan (synthetic)\nTarget: Example Widgets Ltd. (fictional)\nStatus: exploratory\n",
        protection: Protection::Quorum {
            threshold: 2,
            leaves: &["M", "M.S", "M.A"],
            custody: CustodyMode::Hardware,
            minimum_devices: 2,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "board-minutes-2026-08",
        folder: "executive",
        name: "board-minutes-2026-08.md",
        lesson: "Morgan alone (1 of 1).",
        contents: "# Board minutes, August 2026 (synthetic)\n\nAttendance noted. No material resolutions.\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Never,
        },
    },
    FileSeed {
        id: "succession-plan",
        folder: "executive",
        name: "succession-plan.txt",
        lesson: "Morgan alone, and already expired when the lab loaded.",
        contents: "Succession plan (synthetic)\nDraft only; not finalized.\n",
        protection: Protection::Quorum {
            threshold: 1,
            leaves: &["M"],
            custody: CustodyMode::Hardware,
            minimum_devices: 1,
            approval: UnlockApproval::None,
            expires: Expiry::Offset("-1 day"),
        },
    },
];

/// Every slot is sealed under this demo passphrase. It is published in
/// the bundle on purpose: the lab simulates the passphrase prompt, it does
/// not protect anything.
pub fn demo_passphrase(label: &str) -> String {
    format!("lab-demo-{label}")
}
