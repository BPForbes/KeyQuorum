use super::{run, TreeBridgeCommand};
use crate::db;
use crate::key_tree::{self, NodeSpec};
use crate::keys::{self, KeyType};
use rusqlite::Connection;

fn tree() -> (Connection, i64) {
    let mut conn = db::open_in_memory().unwrap();
    let leaf = |label: &str, byte: u8| {
        let id = keys::register_key(&conn, label, KeyType::Encryption, &[byte; 32]).unwrap();
        NodeSpec::Leaf {
            label: label.into(),
            hardware_key_id: id,
            allowed_bridges: vec![],
        }
    };
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![leaf("M.A", 7), leaf("M.B", 9)],
    };
    let key_id = key_tree::split(&mut conn, "org", &[1u8; 32], &spec).unwrap();
    (conn, key_id)
}

fn exec(conn: &Connection, command: TreeBridgeCommand) -> crate::error::Result<String> {
    let mut out = Vec::new();
    run(conn, command, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

#[test]
fn allow_add_list_remove_print_the_cli_output() {
    let (conn, key_id) = tree();
    let allow = TreeBridgeCommand::Allow {
        key_id,
        node: "M.A".into(),
        peer: "M.B".into(),
    };
    assert_eq!(
        exec(&conn, allow).unwrap(),
        "Allowed M.A to bridge to M.B\n"
    );
    let add = TreeBridgeCommand::Add {
        key_id,
        from: "M.B".into(),
        to: "M.A".into(),
    };
    assert_eq!(
        exec(&conn, add).unwrap(),
        "Established bridge M.B <-> M.A\n"
    );
    assert_eq!(
        exec(&conn, TreeBridgeCommand::List { key_id }).unwrap(),
        "Allowed:\n  M.A -> M.B\nEstablished:\n  M.A <-> M.B\n"
    );
    let remove = TreeBridgeCommand::Remove {
        key_id,
        from: "M.A".into(),
        to: "M.B".into(),
    };
    assert_eq!(exec(&conn, remove).unwrap(), "Removed bridge M.A <-> M.B\n");
    assert_eq!(
        exec(&conn, TreeBridgeCommand::List { key_id }).unwrap(),
        "Allowed:\n  M.A -> M.B\nEstablished:\n  (none)\n"
    );
}

#[test]
fn library_refusals_surface_as_errors() {
    let (conn, key_id) = tree();
    let add = TreeBridgeCommand::Add {
        key_id,
        from: "M.A".into(),
        to: "M.B".into(),
    };
    assert!(matches!(
        exec(&conn, add),
        Err(crate::error::Error::BridgeNotWhitelisted)
    ));
}
