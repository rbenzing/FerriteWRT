//! Button handling: evdev record parsing and the short/long press classifier.
//!
//! `gpio-keys` devices emit `EV_KEY` events (value 1 = pressed, 0 = released, 2 = autorepeat).
//! The classifier is fed those events with their timestamps and reports a [`Press`] on
//! release, comparing the held time with the board's `long_press_secs`.

use std::time::Duration;

use owr_board::{Button, ButtonAction};

pub const EV_KEY: u16 = 0x01;
pub const KEY_RESTART: u16 = 0x198;
/// Size of `struct input_event`: `timeval` (2 x `long`) + u16 type + u16 code + i32 value, so
/// 24 bytes with 64-bit longs (aarch64) and 16 with 32-bit longs (arm, mips).
#[cfg(target_pointer_width = "64")]
pub const INPUT_EVENT_SIZE: usize = 24;
/// See the 64-bit definition.
#[cfg(target_pointer_width = "32")]
pub const INPUT_EVENT_SIZE: usize = 16;
/// Width of each `timeval` field (`long`).
const TV_FIELD: usize = (INPUT_EVENT_SIZE - 8) / 2;
const TYPE_AT: usize = 2 * TV_FIELD;
const CODE_AT: usize = TYPE_AT + 2;
const VALUE_AT: usize = CODE_AT + 2;
/// Releases sooner than this after a press are contact bounce, not a press.
pub const DEBOUNCE: Duration = Duration::from_millis(30);

/// One `EV_KEY` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    /// Kernel timestamp. Only differences between events are meaningful.
    pub ts: Duration,
    pub code: u16,
    pub value: i32,
}

/// A native-endian `long` as stored in the record's `timeval`.
#[cfg(target_pointer_width = "64")]
fn decode_long(b: &[u8]) -> Option<i64> {
    Some(i64::from_ne_bytes(b.try_into().ok()?))
}

/// A native-endian `long` as stored in the record's `timeval`.
#[cfg(target_pointer_width = "32")]
fn decode_long(b: &[u8]) -> Option<i64> {
    Some(i64::from(i32::from_ne_bytes(b.try_into().ok()?)))
}

/// Decode one [`INPUT_EVENT_SIZE`]-byte evdev record; `None` for non-key events or short/garbled
/// buffers.
pub fn parse_input_event(buf: &[u8]) -> Option<InputEvent> {
    let rec = buf.get(..INPUT_EVENT_SIZE)?;
    let long_at = |at: usize| decode_long(rec.get(at..at.checked_add(TV_FIELD)?)?);
    let u16_at = |at: usize| {
        Some(u16::from_ne_bytes(
            rec.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    };
    let (sec, usec) = (long_at(0)?, long_at(TV_FIELD)?);
    if u16_at(TYPE_AT)? != EV_KEY || !(0..1_000_000).contains(&usec) {
        return None;
    }
    let code = u16_at(CODE_AT)?;
    let value = i32::from_ne_bytes(rec.get(VALUE_AT..INPUT_EVENT_SIZE)?.try_into().ok()?);
    let ts = Duration::new(
        u64::try_from(sec).ok()?,
        u32::try_from(usec.checked_mul(1000)?).ok()?,
    );
    Some(InputEvent { ts, code, value })
}

/// Map a board keycode name (`"KEY_RESTART"`) or a number (`"0x198"`, `"408"`) to a code.
pub fn keycode_from_name(name: &str) -> Option<u16> {
    match name {
        "KEY_RESTART" => Some(KEY_RESTART),
        "KEY_WPS_BUTTON" => Some(0x211),
        "KEY_WLAN" => Some(238),
        "KEY_RFKILL" => Some(247),
        "BTN_0" => Some(0x100),
        "BTN_1" => Some(0x101),
        other => match other.strip_prefix("0x") {
            Some(hex) => u16::from_str_radix(hex, 16).ok(),
            None => other.parse().ok(),
        },
    }
}

/// Result of classifying a completed press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    Short,
    /// Held for at least the long-press threshold; carries whole seconds held.
    Long(u64),
}

/// Debouncing press classifier for one key.
#[derive(Debug, Clone)]
pub struct Classifier {
    code: u16,
    long_press: Option<Duration>,
    down_at: Option<Duration>,
}

impl Classifier {
    /// `long_press_secs = None` means the button has no long-press behaviour.
    pub fn new(code: u16, long_press_secs: Option<u8>) -> Self {
        Self {
            code,
            long_press: long_press_secs.map(|s| Duration::from_secs(u64::from(s))),
            down_at: None,
        }
    }

    /// Feed one event; returns a [`Press`] when a release completes a valid press.
    pub fn feed(&mut self, ev: InputEvent) -> Option<Press> {
        if ev.code != self.code {
            return None;
        }
        match ev.value {
            1 => {
                // A second "down" without a release is bounce or a lost event: keep the first.
                self.down_at.get_or_insert(ev.ts);
                None
            }
            0 => {
                let down = self.down_at.take()?;
                let held = ev.ts.saturating_sub(down);
                if held < DEBOUNCE {
                    return None;
                }
                match self.long_press {
                    Some(threshold) if held >= threshold => Some(Press::Long(held.as_secs())),
                    _ => Some(Press::Short),
                }
            }
            _ => None, // autorepeat
        }
    }
}

/// A board button wired to its classifier and actions.
#[derive(Debug, Clone)]
pub struct ButtonBinding {
    pub name: String,
    classifier: Classifier,
    short: ButtonAction,
    long: ButtonAction,
}

impl ButtonBinding {
    /// `None` if the board names a keycode we do not know.
    pub fn from_board(b: &Button) -> Option<Self> {
        let code = keycode_from_name(&b.keycode)?;
        Some(Self {
            name: b.name.clone(),
            classifier: Classifier::new(code, b.long_press_secs),
            short: b.short_press,
            long: b.long_press.unwrap_or(ButtonAction::None),
        })
    }

    /// Feed an event; returns the completed press and the action bound to it.
    pub fn feed(&mut self, ev: InputEvent) -> Option<(Press, ButtonAction)> {
        let press = self.classifier.feed(ev)?;
        let action = match press {
            Press::Short => self.short,
            Press::Long(_) => self.long,
        };
        Some((press, action))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn ev(ms: u64, code: u16, value: i32) -> InputEvent {
        InputEvent {
            ts: Duration::from_millis(ms),
            code,
            value,
        }
    }

    fn press(c: &mut Classifier, down_ms: u64, up_ms: u64) -> Option<Press> {
        assert_eq!(c.feed(ev(down_ms, KEY_RESTART, 1)), None);
        c.feed(ev(up_ms, KEY_RESTART, 0))
    }

    #[test]
    fn short_press() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(press(&mut c, 1000, 1400), Some(Press::Short));
    }

    #[test]
    fn long_press_at_and_above_threshold() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(press(&mut c, 0, 4999), Some(Press::Short));
        assert_eq!(press(&mut c, 10_000, 15_000), Some(Press::Long(5)));
        assert_eq!(press(&mut c, 20_000, 28_500), Some(Press::Long(8)));
    }

    #[test]
    fn no_long_press_configured_is_always_short() {
        let mut c = Classifier::new(KEY_RESTART, None);
        assert_eq!(press(&mut c, 0, 60_000), Some(Press::Short));
    }

    #[test]
    fn bounce_is_ignored() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(press(&mut c, 100, 110), None);
        // state was cleared: a real press afterwards works
        assert_eq!(press(&mut c, 500, 900), Some(Press::Short));
    }

    #[test]
    fn duplicate_down_keeps_first_timestamp() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        c.feed(ev(0, KEY_RESTART, 1));
        c.feed(ev(4000, KEY_RESTART, 1));
        assert_eq!(c.feed(ev(5500, KEY_RESTART, 0)), Some(Press::Long(5)));
    }

    #[test]
    fn release_without_press_and_repeat_events_are_ignored() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(c.feed(ev(10, KEY_RESTART, 0)), None);
        c.feed(ev(100, KEY_RESTART, 1));
        assert_eq!(c.feed(ev(600, KEY_RESTART, 2)), None);
        assert_eq!(c.feed(ev(900, KEY_RESTART, 0)), Some(Press::Short));
    }

    #[test]
    fn other_keys_are_ignored() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(c.feed(ev(0, 0x211, 1)), None);
        assert_eq!(c.feed(ev(500, 0x211, 0)), None);
    }

    #[test]
    fn clock_going_backwards_is_not_a_long_press() {
        let mut c = Classifier::new(KEY_RESTART, Some(5));
        assert_eq!(
            press(&mut c, 10_000, 5_000),
            None,
            "negative duration counts as bounce"
        );
    }

    #[cfg(target_pointer_width = "64")]
    fn long_bytes(v: i64) -> Vec<u8> {
        v.to_ne_bytes().to_vec()
    }

    #[cfg(target_pointer_width = "32")]
    fn long_bytes(v: i64) -> Vec<u8> {
        i32::try_from(v).unwrap().to_ne_bytes().to_vec()
    }

    fn raw(sec: i64, usec: i64, typ: u16, code: u16, value: i32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(long_bytes(sec));
        v.extend(long_bytes(usec));
        v.extend(typ.to_ne_bytes());
        v.extend(code.to_ne_bytes());
        v.extend(value.to_ne_bytes());
        v
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn record_size_is_24_on_64_bit() {
        assert_eq!(INPUT_EVENT_SIZE, 24);
        assert_eq!(raw(1, 2, EV_KEY, 3, 1).len(), INPUT_EVENT_SIZE);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn record_size_is_16_on_32_bit() {
        assert_eq!(INPUT_EVENT_SIZE, 16);
        assert_eq!(raw(1, 2, EV_KEY, 3, 1).len(), INPUT_EVENT_SIZE);
    }

    #[test]
    fn layout_offsets_cover_the_record_exactly() {
        assert_eq!(2 * TV_FIELD + 8, INPUT_EVENT_SIZE);
        assert_eq!(VALUE_AT + 4, INPUT_EVENT_SIZE);
    }

    #[test]
    fn parses_evdev_records() {
        let e = parse_input_event(&raw(12, 500_000, EV_KEY, KEY_RESTART, 1)).unwrap();
        assert_eq!(e.ts, Duration::new(12, 500_000_000));
        assert_eq!((e.code, e.value), (KEY_RESTART, 1));
        assert_eq!(parse_input_event(&raw(1, 0, 0 /* EV_SYN */, 0, 0)), None);
        assert_eq!(
            parse_input_event(&raw(1, 0, EV_KEY, 1, 1)[..INPUT_EVENT_SIZE - 1]),
            None,
            "short buffer"
        );
        assert_eq!(
            parse_input_event(&raw(-1, 0, EV_KEY, 1, 1)),
            None,
            "negative time"
        );
        assert_eq!(
            parse_input_event(&raw(1, 2_000_000, EV_KEY, 1, 1)),
            None,
            "bad usec"
        );
        // Extra trailing records in the buffer are ignored by this decoder.
        let mut two = raw(1, 0, EV_KEY, 1, 1);
        two.extend(raw(2, 0, EV_KEY, 1, 0));
        assert_eq!(parse_input_event(&two).unwrap().value, 1);
    }

    #[test]
    fn keycode_names() {
        assert_eq!(keycode_from_name("KEY_RESTART"), Some(0x198));
        assert_eq!(keycode_from_name("KEY_WPS_BUTTON"), Some(0x211));
        assert_eq!(keycode_from_name("0x198"), Some(0x198));
        assert_eq!(keycode_from_name("408"), Some(408));
        assert_eq!(keycode_from_name("KEY_NOPE"), None);
        assert_eq!(keycode_from_name("0xzz"), None);
    }

    #[test]
    fn binding_from_mt6000_board() {
        let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
        let mut b = ButtonBinding::from_board(&board.buttons[0]).unwrap();
        assert_eq!(b.name, "reset");
        assert_eq!(b.feed(ev(0, KEY_RESTART, 1)), None);
        assert_eq!(
            b.feed(ev(300, KEY_RESTART, 0)),
            Some((Press::Short, ButtonAction::Reboot))
        );
        b.feed(ev(1000, KEY_RESTART, 1));
        assert_eq!(
            b.feed(ev(7000, KEY_RESTART, 0)),
            Some((Press::Long(6), ButtonAction::FactoryReset))
        );
    }

    #[test]
    fn binding_rejects_unknown_keycode() {
        let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
        let mut btn = board.buttons[0].clone();
        btn.keycode = "KEY_BOGUS".into();
        assert!(ButtonBinding::from_board(&btn).is_none());
    }
}
