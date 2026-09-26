//! Synthetic seed data for the browser lab. Every name, label, passphrase,
//! and file body here is invented for the demonstration and is public by
//! construction: it ships inside the WASM bundle.

use crate::device::{CustodyMode, UnlockApproval};

pub struct UserSeed {
    pub id: &'static str,
    pub name: &'static str,
    pub label: &'static str,
    pub role: &'static str,
    pub drive: &'static str,
}

pub struct DriveSeed {
    pub id: &'static str,
    pub name: &'static str,
    pub mount: &'static str,
    pub slots: &'static [&'static str],
    pub inserted: bool,
}

pub enum Protection {
    Public,
    Quorum {
        threshold: u8,
        leaves: &'static [&'static str],
        custody: CustodyMode,
        minimum_devices: u8,
        approval: UnlockApproval,
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

pub const USERS: &[UserSeed] = &[
    UserSeed {
        id: "morgan",
        name: "Morgan",
        label: "M",
        role: "Executive",
        drive: "executive",
    },
    UserSeed {
        id: "sarah",
        name: "Sarah",
        label: "M.S",
        role: "Software Manager",
        drive: "engineering",
    },
    UserSeed {
        id: "alice",
        name: "Alice",
        label: "M.S.1",
        role: "Software Engineer",
        drive: "engineering",
    },
    UserSeed {
        id: "bob",
        name: "Bob",
        label: "M.S.2",
        role: "Software Engineer",
        drive: "engineering",
    },
    UserSeed {
        id: "david",
        name: "David",
        label: "M.A",
        role: "Accounting Manager",
        drive: "accounting",
    },
    UserSeed {
        id: "emma",
        name: "Emma",
        label: "M.A.1",
        role: "Accountant",
        drive: "accounting",
    },
    UserSeed {
        id: "chris",
        name: "Chris",
        label: "M.A.2",
        role: "Accountant",
        drive: "accounting",
    },
];

pub const DRIVES: &[DriveSeed] = &[
    DriveSeed {
        id: "engineering",
        name: "Engineering USB",
        mount: "/media/engineering-usb",
        slots: &["M.S", "M.S.1", "M.S.2"],
        inserted: true,
    },
    DriveSeed {
        id: "accounting",
        name: "Accounting USB",
        mount: "/media/accounting-usb",
        slots: &["M.A", "M.A.1", "M.A.2"],
        inserted: false,
    },
    DriveSeed {
        id: "executive",
        name: "Executive USB",
        mount: "/media/executive-usb",
        slots: &["M"],
        inserted: false,
    },
];

pub const FILES: &[FileSeed] = &[
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
        },
    },
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
        },
    },
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
        },
    },
];

/// Every slot is sealed under this demo passphrase. It is published in
/// the bundle on purpose: the lab simulates the passphrase prompt, it does
/// not protect anything.
pub fn demo_passphrase(label: &str) -> String {
    format!("lab-demo-{label}")
}
