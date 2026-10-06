// The Durable Object class around the relay core. It is thin on purpose: the
// storage, the secrets and the wasm bindings go to `createRelayService`, which
// holds everything that can be tested outside Cloudflare.
//
// One object holds the whole relay. It is the single writer the audit hash
// chain, the key tables and the key-delivery letters need, because they are
// written together.
import { DurableObject } from "cloudflare:workers";
import wasmModule from "../relay-wasm/keyquorum_relay_bg.wasm";
import * as bindings from "../relay-wasm/keyquorum_relay.js";
import { createRelayService } from "./relay-service.js";

let instantiated = false;
function instantiate() {
  // Once per isolate. The module was compiled by the platform at upload; this
  // only instantiates it.
  if (!instantiated) {
    bindings.initSync({ module: wasmModule });
    instantiated = true;
  }
}

export class RelayObject extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    instantiate();
    this.service = createRelayService({ storage: ctx.storage, env, bindings });
    ctx.blockConcurrencyWhile(() => this.service.start());
  }

  fetch(request) {
    return this.service.fetch(request);
  }

  // The provider's console, called only by the admin Worker through its binding
  // to this object. The public Worker never calls it, and no fetch route leads
  // here.
  operate(request) {
    return this.service.operate(request);
  }

  ready() {
    return this.service.ready();
  }

  alarm() {
    return this.service.alarm();
  }
}
