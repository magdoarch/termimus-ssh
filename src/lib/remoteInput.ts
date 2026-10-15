/**
 * Browser input → remote desktop input: X11 keysyms (VNC), set-1 scancodes
 * (RDP) and RFB-style pointer button masks (translated for RDP in the backend).
 */

// Keys whose `event.key` names a non-printable key.
const SPECIAL_KEYSYMS: Record<string, number> = {
  Backspace: 0xff08,
  Tab: 0xff09,
  Enter: 0xff0d,
  Pause: 0xff13,
  ScrollLock: 0xff14,
  Escape: 0xff1b,
  Home: 0xff50,
  ArrowLeft: 0xff51,
  ArrowUp: 0xff52,
  ArrowRight: 0xff53,
  ArrowDown: 0xff54,
  PageUp: 0xff55,
  PageDown: 0xff56,
  End: 0xff57,
  PrintScreen: 0xff61,
  Insert: 0xff63,
  ContextMenu: 0xff67,
  NumLock: 0xff7f,
  CapsLock: 0xffe5,
  Delete: 0xffff,
  AltGraph: 0xfe03, // ISO_Level3_Shift
  F1: 0xffbe,
  F2: 0xffbf,
  F3: 0xffc0,
  F4: 0xffc1,
  F5: 0xffc2,
  F6: 0xffc3,
  F7: 0xffc4,
  F8: 0xffc5,
  F9: 0xffc6,
  F10: 0xffc7,
  F11: 0xffc8,
  F12: 0xffc9,
};

// Modifiers by physical key so left/right stay distinct.
const MODIFIER_KEYSYMS: Record<string, number> = {
  ShiftLeft: 0xffe1,
  ShiftRight: 0xffe2,
  ControlLeft: 0xffe3,
  ControlRight: 0xffe4,
  AltLeft: 0xffe9,
  AltRight: 0xffea,
  MetaLeft: 0xffeb, // Super_L
  MetaRight: 0xffec, // Super_R
  OSLeft: 0xffeb,
  OSRight: 0xffec,
  NumpadEnter: 0xff8d, // KP_Enter
};

export const KEYSYM = {
  ControlLeft: 0xffe3,
  AltLeft: 0xffe9,
  Delete: 0xffff,
} as const;

/** PC/AT set-1 scancodes for RDP, by physical key; 0xE0xx = extended key. */
const SCANCODES: Record<string, number> = {
  Escape: 0x01, Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
  Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0a, Digit0: 0x0b, Minus: 0x0c,
  Equal: 0x0d, Backspace: 0x0e, Tab: 0x0f, KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12,
  KeyR: 0x13, KeyT: 0x14, KeyY: 0x15, KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
  BracketLeft: 0x1a, BracketRight: 0x1b, Enter: 0x1c, ControlLeft: 0x1d, KeyA: 0x1e,
  KeyS: 0x1f, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22, KeyH: 0x23, KeyJ: 0x24, KeyK: 0x25,
  KeyL: 0x26, Semicolon: 0x27, Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2a,
  Backslash: 0x2b, KeyZ: 0x2c, KeyX: 0x2d, KeyC: 0x2e, KeyV: 0x2f, KeyB: 0x30,
  KeyN: 0x31, KeyM: 0x32, Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
  NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3a, F1: 0x3b, F2: 0x3c,
  F3: 0x3d, F4: 0x3e, F5: 0x3f, F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44,
  NumLock: 0x45, ScrollLock: 0x46, Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49,
  NumpadSubtract: 0x4a, Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, NumpadAdd: 0x4e,
  Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52, NumpadDecimal: 0x53,
  IntlBackslash: 0x56, F11: 0x57, F12: 0x58,
  NumpadEnter: 0xe01c, ControlRight: 0xe01d, NumpadDivide: 0xe035, PrintScreen: 0xe037,
  AltRight: 0xe038, Home: 0xe047, ArrowUp: 0xe048, PageUp: 0xe049, ArrowLeft: 0xe04b,
  ArrowRight: 0xe04d, End: 0xe04f, ArrowDown: 0xe050, PageDown: 0xe051, Insert: 0xe052,
  Delete: 0xe053, MetaLeft: 0xe05b, MetaRight: 0xe05c, OSLeft: 0xe05b, OSRight: 0xe05c,
  ContextMenu: 0xe05d,
};

export const SCANCODE = {
  ControlLeft: SCANCODES.ControlLeft,
  AltLeft: SCANCODES.AltLeft,
  Delete: SCANCODES.Delete,
} as const;

/** Scancode for the physical key of a keyboard event, if it has one. */
export function scancodeForEvent(event: KeyboardEvent): number | undefined {
  return SCANCODES[event.code];
}

/** Keysym for a keyboard event, or null for keys with no mapping (dead keys etc). */
export function keysymForEvent(event: KeyboardEvent): number | null {
  // AltGr on some layouts reports code "AltRight" with key "AltGraph".
  if (event.key === "AltGraph") return SPECIAL_KEYSYMS.AltGraph;
  const modifier = MODIFIER_KEYSYMS[event.code];
  if (modifier !== undefined) return modifier;
  const special = SPECIAL_KEYSYMS[event.key];
  if (special !== undefined) return special;

  const chars = [...event.key];
  if (chars.length !== 1) return null; // "Dead", "Unidentified", "Process", ...
  const cp = chars[0].codePointAt(0)!;
  // Latin-1 code points are their own keysyms; everything else uses the
  // Unicode keysym range.
  if ((cp >= 0x20 && cp <= 0x7e) || (cp >= 0xa0 && cp <= 0xff)) return cp;
  return 0x01000000 + cp;
}

/** DOM `MouseEvent.buttons` → RFB mask (bit 0 left, 1 middle, 2 right). */
export function rfbButtonMask(domButtons: number): number {
  let mask = 0;
  if (domButtons & 1) mask |= 1;
  if (domButtons & 4) mask |= 2;
  if (domButtons & 2) mask |= 4;
  return mask;
}

/** RFB wheel "buttons": pressed then released once per notch. */
export function rfbWheelBit(event: WheelEvent): number {
  if (event.deltaY < 0) return 1 << 3;
  if (event.deltaY > 0) return 1 << 4;
  if (event.deltaX < 0) return 1 << 5;
  if (event.deltaX > 0) return 1 << 6;
  return 0;
}
