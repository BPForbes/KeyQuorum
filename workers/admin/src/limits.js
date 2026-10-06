// Bounds for the console's one POST route. The relay core holds the same cap
// (`relay::operator::MAX_REQUEST_BYTES`); this is the first line, taken before
// a body is read.
export const MAX_REQUEST_BODY_CONSOLE = 64 * 1024;

// The request body as text, or null when it is larger than `limit` bytes (the
// stream is cancelled, so the rest is never read).
export async function readLimitedText(request, limit) {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) return null;
  const reader = request.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
