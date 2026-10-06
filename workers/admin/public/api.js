// The console's calls to the admin Worker, and the sealed bundle download.
import { describeError } from "./format.js";

export class ApiError extends Error {
  constructor(status, body) {
    super(describeError(status, body));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// One call to the relay's console (POST /api/operate). `lock` is the operator
// lock for an action that changes something; it travels in a header for this
// request only.
export async function operate(op, fields = {}, lock = null) {
  const headers = { "content-type": "application/json", accept: "application/json" };
  if (lock) headers["x-operator-lock"] = lock;
  const response = await fetch("/api/operate", {
    method: "POST",
    headers,
    body: JSON.stringify({ op, ...fields }),
    credentials: "same-origin",
    cache: "no-store",
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // not JSON: leave body null
  }
  if (!response.ok) throw new ApiError(response.status, body);
  return body;
}

export async function getJson(path) {
  const response = await fetch(path, { headers: { accept: "application/json" }, credentials: "same-origin" });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // not JSON
  }
  return { status: response.status, body };
}

export function errorText(error) {
  if (error instanceof ApiError) return error.message;
  return "Could not reach the console. Check your connection and try again.";
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
