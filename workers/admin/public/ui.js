// Small DOM helpers. Everything the page shows is created as an element and set
// with textContent, never parsed from a string, so nothing a client or the relay
// sends can become markup.

export function h(tag, attrs = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === "class") element.className = value;
    else if (name === "text") element.textContent = value;
    else if (name === "on") {
      for (const [type, handler] of Object.entries(value)) element.addEventListener(type, handler);
    } else if (value === true) element.setAttribute(name, "");
    else element.setAttribute(name, String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}

export function clear(element) {
  while (element.firstChild) element.firstChild.remove();
}

export function badge(text, kind = "plain") {
  return h("span", { class: `badge ${kind}`, text });
}

export function notice(kind, text) {
  return h("p", { class: `notice ${kind}`, role: kind === "bad" ? "alert" : "status", text });
}

export function empty(text) {
  return h("p", { class: "empty", text });
}

// columns: [{ label, cell(row) -> Node | string, align? }]
export function table(columns, rows, emptyText = "Nothing to show.") {
  if (!rows || rows.length === 0) return empty(emptyText);
  const head = h("tr", {}, columns.map((c) => h("th", { scope: "col", class: c.align === "end" ? "end" : null, text: c.label })));
  const body = rows.map((row) =>
    h("tr", {}, columns.map((c) => h("td", { class: c.align === "end" ? "end" : null }, c.cell(row)))),
  );
  return h("div", { class: "scroll" }, h("table", {}, h("thead", {}, head), h("tbody", {}, body)));
}

export function card(title, value, detail) {
  return h(
    "div",
    { class: "card" },
    h("div", { class: "card-title", text: title }),
    h("div", { class: "card-value", text: String(value) }),
    detail ? h("div", { class: "card-detail", text: detail }) : null,
  );
}

export function section(title, ...children) {
  const heading = h("h2", { text: title });
  return h("section", {}, heading, ...children);
}

let counter = 0;
export function uid(prefix) {
  counter += 1;
  return `${prefix}-${counter}`;
}

// A labelled field. `control` is an input, select or textarea.
export function field(label, control, hint) {
  if (!control.id) control.id = uid("f");
  const parts = [h("label", { for: control.id, text: label }), control];
  if (hint) {
    const note = h("small", { id: `${control.id}-hint`, text: hint });
    control.setAttribute("aria-describedby", note.id);
    parts.push(note);
  }
  return h("div", { class: "field" }, parts);
}

// The operator lock input. Held only in the field, cleared after every use,
// never kept in a variable, storage or the URL.
export function lockField() {
  const input = h("input", {
    type: "password",
    autocomplete: "off",
    spellcheck: "false",
    autocapitalize: "off",
    placeholder: "Operator lock",
    required: true,
  });
  return {
    node: field("Operator lock", input, "Needed for this action only. It is sent with this request and never stored by this page."),
    read: () => input.value.trim(),
    clear: () => {
      input.value = "";
    },
    focus: () => input.focus(),
  };
}

// Runs `task` with the button disabled and `status` showing progress or the
// failure, so a double click cannot send a request twice.
export async function busy(button, status, task, describe) {
  button.disabled = true;
  clear(status);
  status.append(notice("plain", "Working…"));
  try {
    const outcome = await task();
    clear(status);
    return outcome;
  } catch (error) {
    clear(status);
    status.append(notice("bad", describe(error)));
    return undefined;
  } finally {
    button.disabled = false;
  }
}
