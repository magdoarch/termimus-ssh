/**
 * Browser input → RFB (VNC) input: X11 keysyms and pointer button masks.
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
