// One enrollment request handed from the file tool to the Issue form. Held in
// memory only, for this page's life: never in storage or the address, and gone
// once the form takes it.
let held = null;

export const stash = {
  put(value) {
    held = value;
  },
  take() {
    const value = held;
    held = null;
    return value;
  },
};
