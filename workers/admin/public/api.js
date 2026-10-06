// The console's calls to the admin Worker, and the sealed bundle download.
import { describeError, outcomeUnknown } from "./format.js";

export class ApiError extends Error {
  constructor(status, body) {
    super(describeError(status, body));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.unknownOutcome = outcomeUnknown(status, body);
  }
}

// An error for a request that got no answer at all (the network, or a response
// that never arrived): a change that did this may have been made.
export class NetworkError extends Error {
  constructor() {
    super("The console did not get an answer. If this was a change, it may have been made: submit again with the same operation id and it will be done once at most.");
    this.name = "NetworkError";
    this.unknownOutcome = true;
  }
}

function withQuery(path, query) {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(name, String(value));
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}

// One call to the console API. A change passes an `operationId` (sent as the
// Idempotency-Key) and the operator `lock` (sent as x-operator-lock, for this
// request only). Nothing is kept: the lock is not stored anywhere by this page.
export async function api(method, path, { query, body, lock, operationId } = {}) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (lock) headers["x-operator-lock"] = lock;
  if (operationId) headers["idempotency-key"] = operationId;
  let response;
  try {
    response = await fetch(withQuery(path, query), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new NetworkError();
  }
  let parsed = null;
  try {
    parsed = await response.json();
  } catch {
    // not JSON: leave it null
  }
  if (!response.ok) throw new ApiError(response.status, parsed);
  return parsed;
}

export const get = (path, query) => api("GET", path, { query });

export function errorText(error) {
  if (error instanceof ApiError || error instanceof NetworkError) return error.message;
  return "Something went wrong in the console. Reload the page and try again.";
}

// A new operation id, one per attempt at a change.
export function newOperationId() {
  return crypto.randomUUID();
}

// Hands a base64 file to the browser as a download.
export function downloadBase64(filename, base64, type = "application/octet-stream") {
  const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
