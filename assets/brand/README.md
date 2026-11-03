# FerriteWRT brand assets

The mark is iron's periodic-table tile. In the wordmark it stands in for the first two
letters, so the lockup reads **[Fe]rriteWRT**: "Fe" and "rrite" are the same letters at
the same size, the frame is drawn around the first two, and "WRT" carries the accent.

Every file here is plain SVG paths. Nothing depends on a font being installed or loaded.

| File | Use |
|---|---|
| `lockup-light.svg`, `lockup-dark.svg` | README, website, anywhere the page colour is fixed. Pair them with `<picture>` and `prefers-color-scheme`. |
| `lockup.svg` | Inline or `<use>`: ink is `currentColor`, the accent is fixed. |
| `mark-light.svg`, `mark-dark.svg`, `mark.svg` | The tile alone with the atomic number, for 24 px and up (avatars, splash). |
| `favicon.svg` | The tile without the number, ink chosen by the browser's colour scheme. Copied to `crates/owr-api/ui/favicon.svg`. |

The web UI's icon sprite (`crates/owr-api/ui/icons.svg`) carries the same geometry as
`#i-brand` (full lockup), `#i-brand-min` (no atomic number, used in the header bar) and
`#i-brand-mark` (the small tile).

## Colour

Two colours only. **Ink** is whatever the surrounding text colour is, so one asset works in
both themes. The **accent** is one value on light and dark, chosen at mid lightness so it
clears 4:1 against both white and near-black:

| Role | Value |
|---|---|
| Accent | `#2F6FEF` |
| Ink, light theme | `#171A20` |
| Ink, dark theme | `#E8EBF0` |
| Atomic number | ink at 55 % opacity |

Rules: the atomic number appears at 24 px type and above and is dropped below that; the
frame is never filled; "WRT" is the only part that takes the accent.

## Regenerating

The letterforms are Manrope ExtraBold (OFL). `generate.js` lays the text out with the real
font and writes the paths, so the geometry stays exact if the lockup changes:

```bash
npm i fontkit@2
curl -LO https://github.com/google/fonts/raw/main/ofl/manrope/Manrope%5Bwght%5D.ttf
node assets/brand/generate.js 'Manrope[wght].ttf' .
```

It rewrites every SVG here, the UI favicon and the three brand symbols in the UI sprite.
