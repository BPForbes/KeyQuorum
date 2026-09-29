// The only bridge to the Rust lab. Each method is one WASM call that runs
// one KeyQuorum action and returns the outcome plus a full snapshot; the UI
// never reads state piecemeal. Nothing here talks to a network.
import init, { KeyQuorumLab } from "../wasm/keyquorum_lab.js";
import type { ActionResult, FileView } from "./types";

export class LabClient {
  private constructor(private readonly lab: KeyQuorumLab) {}

  static async create(): Promise<LabClient> {
    await init();
    return new LabClient(new KeyQuorumLab());
  }

  private call(json: string): ActionResult {
    return JSON.parse(json) as ActionResult;
  }

  snapshot(): ActionResult {
    return this.call(this.lab.snapshot());
  }

  reset(): ActionResult {
    return this.call(this.lab.reset());
  }

  switchUser(id: string): ActionResult {
    return this.call(this.lab.switch_user(id));
  }

  insertDrive(id: string): ActionResult {
    return this.call(this.lab.insert_drive(id));
  }

  ejectDrive(id: string): ActionResult {
    return this.call(this.lab.eject_drive(id));
  }

  moveSlot(label: string, toDriveId: string): ActionResult {
    return this.call(this.lab.move_slot(label, toDriveId));
  }

  inspectFile(id: string): FileView | null {
    return JSON.parse(this.lab.inspect_file(id)) as FileView | null;
  }

  unlockFile(id: string): ActionResult {
    return this.call(this.lab.unlock_file(id));
  }

  sendFile(fileId: string, recipientId: string): ActionResult {
    return this.call(this.lab.send_file(fileId, recipientId));
  }

  receive(relayId: number): ActionResult {
    return this.call(this.lab.receive(relayId));
  }

  reject(relayId: number): ActionResult {
    return this.call(this.lab.reject(relayId));
  }

  refreshInbox(): ActionResult {
    return this.call(this.lab.refresh_inbox());
  }

  runCommand(line: string): ActionResult {
    return this.call(this.lab.run_command(line));
  }

  noteUi(kind: string, title: string): ActionResult {
    return this.call(this.lab.note_ui(kind, title));
  }

  lockPasswordFile(name: string, contents: string, password: string, pin?: string): ActionResult {
    return this.call(this.lab.lock_password_file(name, contents, password, pin));
  }

  unlockPasswordFile(id: number, password: string, pin?: string): ActionResult {
    return this.call(this.lab.unlock_password_file(id, password, pin));
  }

  provisionSlot(driveId: string, label: string, passphrase: string): ActionResult {
    return this.call(this.lab.provision_slot(driveId, label, passphrase));
  }

  deviceLog(driveId: string): ActionResult {
    return this.call(this.lab.device_log(driveId));
  }

  revokeKey(nodeLabel: string): ActionResult {
    return this.call(this.lab.revoke_key(nodeLabel));
  }

  transferCopy(label: string, toDriveId: string, passphrase: string): ActionResult {
    return this.call(this.lab.transfer_copy(label, toDriveId, passphrase));
  }

  exportFile(id: number, recipientLabel: string, password: string): ActionResult {
    return this.call(this.lab.export_file(id, recipientLabel, password));
  }

  viewExport(id: number): ActionResult {
    return this.call(this.lab.view_export(id));
  }

  createFileShare(fileId: number, ttlSeconds: number, pin?: string): ActionResult {
    return this.call(this.lab.create_file_share(fileId, ttlSeconds, pin));
  }

  redeemFileShare(shareId: number, token: string, pin?: string): ActionResult {
    return this.call(this.lab.redeem_file_share(shareId, token, pin));
  }

  revokeFileShare(shareId: number): ActionResult {
    return this.call(this.lab.revoke_file_share(shareId));
  }

  signFile(fileId: string): ActionResult {
    return this.call(this.lab.sign_file(fileId));
  }

  verifySignature(signatureId: number): ActionResult {
    return this.call(this.lab.verify_signature(signatureId));
  }

  registerLeaf(driveId: string, slotLabel: string, parentLabel: string): ActionResult {
    return this.call(this.lab.register_leaf(driveId, slotLabel, parentLabel));
  }

  reissueKey(nodeLabel: string, toDriveId: string, passphrase: string): ActionResult {
    return this.call(this.lab.reissue_key(nodeLabel, toDriveId, passphrase));
  }

  proposeRestructure(): ActionResult {
    return this.call(this.lab.propose_restructure());
  }

  countersignRestructure(passphrase: string): ActionResult {
    return this.call(this.lab.countersign_restructure(passphrase));
  }

  historyTrack(name: string, text: string): ActionResult {
    return this.call(this.lab.history_track(name, text));
  }

  historyCheckin(path: string, text: string, signed: boolean, label?: string): ActionResult {
    return this.call(this.lab.history_checkin(path, text, signed, label));
  }

  historySign(path: string, revision?: string): ActionResult {
    return this.call(this.lab.history_sign(path, revision));
  }

  historyCountersign(path: string, revision?: string): ActionResult {
    return this.call(this.lab.history_countersign(path, revision));
  }

  historyMerge(path: string, label?: string): ActionResult {
    return this.call(this.lab.history_merge(path, label));
  }

  historyVerify(path: string): ActionResult {
    return this.call(this.lab.history_verify(path));
  }

  historyReview(path: string): ActionResult {
    return this.call(this.lab.history_review(path));
  }

  historyShare(path: string, toUser: string): ActionResult {
    return this.call(this.lab.history_share(path, toUser));
  }

  historyReceive(letterId: number, accept: boolean): ActionResult {
    return this.call(this.lab.history_receive(letterId, accept));
  }

  historyAck(letterId: number): ActionResult {
    return this.call(this.lab.history_ack(letterId));
  }
}
