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

  answerApproval(id: number, approve: boolean): ActionResult {
    return this.call(this.lab.answer_approval(id, approve));
  }

  runCommand(line: string): ActionResult {
    return this.call(this.lab.run_command(line));
  }
}
