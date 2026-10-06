// The public Worker's entry module: the fetch handler and the Durable Object
// class, which wrangler requires to be exported from the same module. The
// handler is in worker.js so that it can be tested without Cloudflare's runtime;
// the class imports it (`cloudflare:workers`) and the WebAssembly relay core.
export { default } from "./worker.js";
export { RelayObject } from "./relay-object.js";
