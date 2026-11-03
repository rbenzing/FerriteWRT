//! Channel plan arithmetic: validity per band, VHT/HE centre channels, HT40 sign.

use crate::model::Band;

/// 5 GHz 80 MHz blocks: (first primary, last primary, centre).
const BLOCKS_80_5G: [(u16, u16, u16); 6] = [
    (36, 48, 42),
    (52, 64, 58),
    (100, 112, 106),
    (116, 128, 122),
    (132, 144, 138),
    (149, 161, 155),
];
/// 5 GHz 160 MHz blocks.
const BLOCKS_160_5G: [(u16, u16, u16); 2] = [(36, 64, 50), (100, 128, 114)];

/// Whether `channel` is a valid primary channel number for `band`.
///
/// 2.4 GHz: 1..=14. 5 GHz: 36..=64, 100..=144 and 149..=177 in steps of 4.
/// 6 GHz: 1..=233 in steps of 4 (1, 5, 9, ...).
pub fn is_valid_channel(band: Band, channel: u16) -> bool {
    match band {
        Band::G2 => (1..=14).contains(&channel),
        Band::G5 => [(36, 64), (100, 144), (149, 177)].iter().any(|&(lo, hi)| {
            (lo..=hi).contains(&channel) && channel.saturating_sub(lo).is_multiple_of(4)
        }),
        Band::G6 => (1..=233).contains(&channel) && channel.saturating_sub(1).is_multiple_of(4),
    }
}

/// Centre channel index (`*_oper_centr_freq_seg0_idx`) for an 80 or 160 MHz channel
/// whose primary is `primary`. `None` for other widths, unsupported 2.4 GHz use, or a
/// primary that does not lie in a defined block.
pub fn center_channel(band: Band, primary: u16, width_mhz: u16) -> Option<u16> {
    match band {
        Band::G2 => None,
        Band::G5 => {
            let table: &[(u16, u16, u16)] = match width_mhz {
                80 => &BLOCKS_80_5G,
                160 => &BLOCKS_160_5G,
                _ => return None,
            };
            table
                .iter()
                .find(|&&(lo, hi, _)| (lo..=hi).contains(&primary))
                .map(|&(_, _, centre)| centre)
        }
        Band::G6 => {
            // 6 GHz blocks are aligned to channel 1: blocks of 16 (80 MHz) / 32 (160 MHz)
            // channel numbers; the centre sits 6 / 14 above the block start.
            let (span, offset, max_block) = match width_mhz {
                80 => (16u16, 7u16, 13u16),
                160 => (32, 15, 6),
                _ => return None,
            };
            let block = primary.checked_sub(1)?.checked_div(span)?;
            (block <= max_block).then(|| block.saturating_mul(span).saturating_add(offset))
        }
    }
}

/// HT40 secondary-channel direction for `primary`: `'+'` if the secondary channel is
/// above the primary, `'-'` if below.
///
/// 2.4 GHz: channels 1..=7 use `+`, 8 and above use `-`. 5 GHz: the lower channel of each
/// 40 MHz pair (36, 44, ..., 100, 108, ..., 149, 157, ...) uses `+`.
pub(crate) fn ht40_sign(band: Band, primary: u16) -> char {
    match band {
        Band::G2 => {
            if primary <= 7 {
                '+'
            } else {
                '-'
            }
        }
        Band::G5 | Band::G6 => {
            let base = match primary {
                149.. => 149,
                100..=148 => 100,
                _ => 36,
            };
            if (primary.saturating_sub(base) / 4).is_multiple_of(2) {
                '+'
            } else {
                '-'
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn center_80_blocks() {
        for (primary, centre) in [
            (36, 42),
            (48, 42),
            (52, 58),
            (64, 58),
            (100, 106),
            (112, 106),
            (116, 122),
            (128, 122),
            (132, 138),
            (144, 138),
            (149, 155),
            (161, 155),
        ] {
            assert_eq!(
                center_channel(Band::G5, primary, 80),
                Some(centre),
                "ch {primary}"
            );
        }
    }

    #[test]
    fn center_160_blocks() {
        assert_eq!(center_channel(Band::G5, 36, 160), Some(50));
        assert_eq!(center_channel(Band::G5, 64, 160), Some(50));
        assert_eq!(center_channel(Band::G5, 100, 160), Some(114));
        assert_eq!(center_channel(Band::G5, 128, 160), Some(114));
    }

    #[test]
    fn center_undefined_cases() {
        assert_eq!(center_channel(Band::G5, 132, 160), None);
        assert_eq!(center_channel(Band::G5, 165, 80), None);
        assert_eq!(center_channel(Band::G5, 36, 40), None);
        assert_eq!(center_channel(Band::G2, 6, 80), None);
    }

    #[test]
    fn center_6ghz() {
        assert_eq!(center_channel(Band::G6, 1, 80), Some(7));
        assert_eq!(center_channel(Band::G6, 29, 80), Some(23));
        assert_eq!(center_channel(Band::G6, 1, 160), Some(15));
        assert_eq!(center_channel(Band::G6, 33, 160), Some(47));
        assert_eq!(center_channel(Band::G6, 229, 160), None);
        assert_eq!(center_channel(Band::G6, 0, 80), None);
    }

    #[test]
    fn valid_channels_2g() {
        assert!(is_valid_channel(Band::G2, 1));
        assert!(is_valid_channel(Band::G2, 14));
        assert!(!is_valid_channel(Band::G2, 0));
        assert!(!is_valid_channel(Band::G2, 15));
    }

    #[test]
    fn valid_channels_5g() {
        for ch in [36, 40, 64, 100, 144, 149, 165, 177] {
            assert!(is_valid_channel(Band::G5, ch), "{ch}");
        }
        for ch in [0, 34, 37, 68, 96, 148, 150, 181] {
            assert!(!is_valid_channel(Band::G5, ch), "{ch}");
        }
    }

    #[test]
    fn valid_channels_6g() {
        assert!(is_valid_channel(Band::G6, 1));
        assert!(is_valid_channel(Band::G6, 233));
        assert!(!is_valid_channel(Band::G6, 2));
        assert!(!is_valid_channel(Band::G6, 237));
    }

    #[test]
    fn ht40_sign_2g() {
        assert_eq!(ht40_sign(Band::G2, 1), '+');
        assert_eq!(ht40_sign(Band::G2, 7), '+');
        assert_eq!(ht40_sign(Band::G2, 8), '-');
        assert_eq!(ht40_sign(Band::G2, 13), '-');
    }

    #[test]
    fn ht40_sign_5g() {
        for (ch, sign) in [
            (36, '+'),
            (40, '-'),
            (44, '+'),
            (48, '-'),
            (100, '+'),
            (104, '-'),
            (149, '+'),
            (153, '-'),
        ] {
            assert_eq!(ht40_sign(Band::G5, ch), sign, "ch {ch}");
        }
    }
}
