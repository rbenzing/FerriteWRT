//! LED behaviour per board role (pure): which sysfs files to write for a boot state.
//!
//! Boot uses the `heartbeat` trigger, failsafe a fast `timer` blink (100 ms on/off), running
//! solid on. LEDs whose roles do not match the state are switched off, so on the GL-MT6000
//! the blue LED heartbeats during boot and the white one lights when running.

use std::path::{Path, PathBuf};

use owr_board::{Led, LedRole};

/// Standard location of LED class devices.
pub const LEDS_ROOT: &str = "/sys/class/leds";

/// Boot state a LED can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedState {
    Boot,
    Failsafe,
    Running,
    Upgrade,
}

impl LedState {
    const fn role(self) -> LedRole {
        match self {
            Self::Boot => LedRole::Boot,
            Self::Failsafe => LedRole::Failsafe,
            Self::Running => LedRole::Running,
            Self::Upgrade => LedRole::Upgrade,
        }
    }
}

/// One sysfs write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsWrite {
    pub path: PathBuf,
    pub value: String,
}

fn safe_led_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
}

fn write(dir: &Path, file: &str, value: &str) -> SysfsWrite {
    SysfsWrite {
        path: dir.join(file),
        value: value.to_owned(),
    }
}

/// Ordered writes that put every board LED into `state`. `root` is normally [`LEDS_ROOT`].
pub fn led_writes(root: &Path, leds: &[Led], state: LedState) -> Vec<SysfsWrite> {
    let mut out = Vec::new();
    for led in leds.iter().filter(|l| safe_led_name(&l.name)) {
        let dir = root.join(&led.name);
        if !led.roles.contains(&state.role()) {
            out.push(write(&dir, "trigger", "none"));
            out.push(write(&dir, "brightness", "0"));
            continue;
        }
        match state {
            LedState::Boot => out.push(write(&dir, "trigger", "heartbeat")),
            LedState::Failsafe | LedState::Upgrade => {
                let ms = if state == LedState::Failsafe {
                    "100"
                } else {
                    "250"
                };
                // delay_* appear only after the timer trigger is selected.
                out.push(write(&dir, "trigger", "timer"));
                out.push(write(&dir, "delay_on", ms));
                out.push(write(&dir, "delay_off", ms));
            }
            LedState::Running => {
                out.push(write(&dir, "trigger", "none"));
                out.push(write(&dir, "brightness", "1"));
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn leds() -> Vec<Led> {
        owr_board::builtin("glinet_gl-mt6000").unwrap().leds
    }

    fn as_pairs(w: &[SysfsWrite]) -> Vec<(String, &str)> {
        w.iter()
            .map(|x| {
                let rel = x.path.strip_prefix(LEDS_ROOT).unwrap();
                (rel.to_string_lossy().replace('\\', "/"), x.value.as_str())
            })
            .collect()
    }

    fn pair(path: &str, value: &str) -> (String, String) {
        (path.to_owned(), value.to_owned())
    }

    fn owned(w: &[SysfsWrite]) -> Vec<(String, String)> {
        as_pairs(w)
            .into_iter()
            .map(|(p, v)| (p, v.to_owned()))
            .collect()
    }

    #[test]
    fn boot_heartbeats_boot_led_and_darkens_others() {
        let w = led_writes(Path::new(LEDS_ROOT), &leds(), LedState::Boot);
        assert_eq!(
            owned(&w),
            [
                pair("blue:run/trigger", "heartbeat"),
                pair("white:system/trigger", "none"),
                pair("white:system/brightness", "0"),
            ]
        );
    }

    #[test]
    fn failsafe_blinks_fast() {
        let w = led_writes(Path::new(LEDS_ROOT), &leds(), LedState::Failsafe);
        assert_eq!(
            owned(&w).get(..3),
            Some(
                &[
                    pair("blue:run/trigger", "timer"),
                    pair("blue:run/delay_on", "100"),
                    pair("blue:run/delay_off", "100"),
                ][..]
            )
        );
    }

    #[test]
    fn running_is_solid_on_for_running_role_only() {
        let w = led_writes(Path::new(LEDS_ROOT), &leds(), LedState::Running);
        assert_eq!(
            owned(&w),
            [
                pair("blue:run/trigger", "none"),
                pair("blue:run/brightness", "0"),
                pair("white:system/trigger", "none"),
                pair("white:system/brightness", "1"),
            ]
        );
    }

    #[test]
    fn trigger_is_always_written_before_dependent_files() {
        for state in [
            LedState::Boot,
            LedState::Failsafe,
            LedState::Running,
            LedState::Upgrade,
        ] {
            let w = led_writes(Path::new(LEDS_ROOT), &leds(), state);
            for led in ["blue:run", "white:system"] {
                let files: Vec<_> = w
                    .iter()
                    .filter(|x| {
                        x.path
                            .parent()
                            .and_then(Path::file_name)
                            .is_some_and(|n| n == led)
                    })
                    .map(|x| x.path.file_name().unwrap().to_string_lossy().into_owned())
                    .collect();
                assert_eq!(
                    files.first().map(String::as_str),
                    Some("trigger"),
                    "{led} {state:?}"
                );
            }
        }
    }

    #[test]
    fn hostile_led_names_are_skipped() {
        let mut l = leds();
        for led in &mut l {
            led.name = "../../etc".into();
        }
        l[1].name = String::new();
        assert_eq!(
            led_writes(Path::new(LEDS_ROOT), &l, LedState::Boot),
            Vec::new()
        );
    }
}
