#!/usr/bin/env node
// FerriteWRT brand asset generator.
//
// Converts the Manrope ExtraBold letterforms of the approved lockup into SVG paths so no
// asset depends on a web font. Geometry mirrors the approved concept page exactly:
//   lockup  = [Fe] tile (border .07em, radius .2em, padding .3em .15em .08em .13em,
//             "26" at .3em in the top-left) + "rrite" (ink) + "WRT" (accent), no gap.
//   mark    = standalone tile on a 24-unit grid, with (>= 24 px) or without (favicon) the 26.
//
// Usage:  node generate.js <Manrope[wght].ttf> <repo-root>
//   npm i fontkit@2   and   https://github.com/google/fonts/raw/main/ofl/manrope/Manrope%5Bwght%5D.ttf
// Writes assets/brand/*.svg, crates/owr-api/ui/favicon.svg and replaces the brand symbols in
// crates/owr-api/ui/icons.svg.

const fs = require('fs');
const path = require('path');
const fontkit = require('fontkit');

const [fontFile, repo] = process.argv.slice(2);
if (!fontFile || !repo) { console.error('usage: generate.js <Manrope[wght].ttf> <repo-root>'); process.exit(2); }

const base = fontkit.openSync(fontFile);
const font = base.getVariation({ wght: 800 });
const UPM = font.unitsPerEm;
// CSS places the baseline of a line-height:1 box at half-leading + ascent.
const ASC = font.ascent / UPM, DESC = -font.descent / UPM;
const BASELINE_FROM_TOP = (1 - (ASC + DESC)) / 2 + ASC;   // em, for line-height: 1

const INK = { light: '#171A20', dark: '#E8EBF0' };
const MUTED = { light: '#6B7280', dark: '#9AA3B2' };
const ACCENT = '#2F6FEF';
const r3 = n => Math.round(n * 1000) / 1000;

/** Path data for `text` at font size `size`, left edge `x`, baseline `y`; returns {d, advance}. */
function text(str, size, x, y, letterSpacing = 0) {
  const run = font.layout(str);
  const s = size / UPM;
  let d = '', pen = x;
  run.glyphs.forEach((g, i) => {
    const p = run.positions[i];
    const gx = pen + p.xOffset * s, gy = y - p.yOffset * s;
    const svg = g.path.transform(s, 0, 0, -s, gx, gy).toSVG();
    if (svg) d += svg;
    pen += p.xAdvance * s + letterSpacing * size;
  });
  // toSVG emits full-precision floats; round them.
  d = d.replace(/-?\d+\.\d{4,}/g, m => r3(Number(m)));
  return { d, advance: pen - x };
}
function width(str, size, letterSpacing = 0) { return text(str, size, 0, 0, letterSpacing).advance; }

function roundedRect(x, y, w, h, r) {
  return `M${r3(x + r)} ${r3(y)}h${r3(w - 2 * r)}a${r} ${r} 0 0 1 ${r} ${r}v${r3(h - 2 * r)}a${r} ${r} 0 0 1 -${r} ${r}h-${r3(w - 2 * r)}a${r} ${r} 0 0 1 -${r} -${r}v-${r3(h - 2 * r)}a${r} ${r} 0 0 1 ${r} -${r}z`;
}

// ---------------------------------------------------------------- lockup (units: 1/100 em)
function lockup({ ink, muted, accent, withNumber = true }) {
  const F = 100, LS = -0.02;                       // font size, letter-spacing (em)
  const border = .07 * F, radius = .2 * F;
  // Below 24 px type the atomic number is dropped and the frame hugs the letters (padding-top .1em).
  const pad = { top: (withNumber ? .3 : .1) * F, right: .15 * F, bottom: .08 * F, left: .13 * F };
  const gap = .09 * F;
  const baseline = 200;                            // y of the word's baseline
  const x0 = border + pad.left + 4;                // left edge of "Fe" (4 = outer margin)

  const fe = text('Fe', F, x0, baseline, LS);
  const feW = fe.advance - LS * F;                 // CSS letter-spacing trails the last glyph; the frame hugs the glyphs
  const inner = { top: baseline - BASELINE_FROM_TOP * F - pad.top, bottom: baseline + (1 - BASELINE_FROM_TOP) * F + pad.bottom,
                  left: x0 - pad.left, right: x0 + feW + pad.right };
  const frame = { x: inner.left - border / 2, y: inner.top - border / 2, w: inner.right - inner.left + border, h: inner.bottom - inner.top + border };
  const num = text('26', .3 * F, inner.left + .13 * F, inner.top + .1 * F + BASELINE_FROM_TOP * .3 * F);
  const wordX = inner.right + border + gap;
  const rrite = text('rrite', F, wordX, baseline, LS);
  const wrt = text('WRT', F, wordX + rrite.advance, baseline, LS);
  const right = wordX + rrite.advance + wrt.advance - LS * F + 4;
  const top = frame.y - border / 2 - 4, bottom = Math.max(frame.y + frame.h + border / 2, baseline + DESC * F) + 4;
  const vb = `0 ${r3(top)} ${r3(right)} ${r3(bottom - top)}`;
  // When no separate muted colour is given the "26" is the ink at reduced opacity.
  const numAttr = muted ? `fill="${muted}"` : `fill="${ink}" opacity=".55"`;
  const body = [
    `<path d="${roundedRect(frame.x, frame.y, frame.w, frame.h, radius)}" fill="none" stroke="${ink}" stroke-width="${r3(border)}"/>`,
    ...(withNumber ? [`<path d="${num.d}" ${numAttr}/>`] : []),
    `<path d="${fe.d}${rrite.d}" fill="${ink}"/>`,
    `<path d="${wrt.d}" fill="${accent}"/>`,
  ];
  return { vb, w: right, h: bottom - top, body,
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}" role="img" aria-label="FerriteWRT">\n  ${body.join('\n  ')}\n</svg>\n` };
}

// ---------------------------------------------------------------- mark (24-unit grid)
function mark({ ink, muted, withNumber, stroke }) {
  const parts = [];
  parts.push(`<path d="${roundedRect(1.9, 1.9, 20.2, 20.2, 4)}" fill="none" stroke="${ink}" stroke-width="${stroke}"/>`);
  if (withNumber) {
    parts.push(`<path d="${text('26', 5.6, 4.4, 8.3).d}" fill="${muted}"/>`);
    const w = width('Fe', 14.2, -0.4 / 14.2);
    parts.push(`<path d="${text('Fe', 14.2, 12.5 - (w + 0.4) / 2, 19.9, -0.4 / 14.2).d}" fill="${ink}"/>`);
  } else {
    const w = width('Fe', 14.4, -0.4 / 14.4);
    parts.push(`<path d="${text('Fe', 14.4, 12.4 - (w + 0.4) / 2, 17.4, -0.4 / 14.4).d}" fill="${ink}"/>`);
  }
  return parts.join('\n  ');
}
const markSvg = (body, extra = '') => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" role="img" aria-label="FerriteWRT">${extra}
  ${body}
</svg>
`;

// ---------------------------------------------------------------- write
const out = p => path.join(repo, p);
fs.mkdirSync(out('assets/brand'), { recursive: true });

// README / web: fixed-colour variants for <picture>.
fs.writeFileSync(out('assets/brand/lockup-light.svg'), lockup({ ink: INK.light, muted: MUTED.light, accent: ACCENT }).svg);
fs.writeFileSync(out('assets/brand/lockup-dark.svg'), lockup({ ink: INK.dark, muted: MUTED.dark, accent: ACCENT }).svg);
fs.writeFileSync(out('assets/brand/mark-light.svg'), markSvg(mark({ ink: INK.light, muted: MUTED.light, withNumber: true, stroke: 1.8 })));
fs.writeFileSync(out('assets/brand/mark-dark.svg'), markSvg(mark({ ink: INK.dark, muted: MUTED.dark, withNumber: true, stroke: 1.8 })));
// Theme-following variants: ink = currentColor (the "26" is ink at reduced opacity), fixed accent.
const lk = lockup({ ink: 'currentColor', accent: ACCENT });
fs.writeFileSync(out('assets/brand/lockup.svg'), lk.svg);
fs.writeFileSync(out('assets/brand/mark.svg'), markSvg(mark({ ink: 'currentColor', muted: 'currentColor', withNumber: true, stroke: 1.8 })
  .replace(/<path d="([^"]*)" fill="currentColor"\/>/, '<path d="$1" fill="currentColor" opacity=".55"/>')));

// Favicon: the small tile, ink chosen by the browser's colour scheme (SVG favicons honour this).
const favicon = markSvg(mark({ ink: 'var(--ink)', muted: 'var(--ink)', withNumber: false, stroke: 2 }),
  `\n  <style>:root{--ink:${INK.light}}@media (prefers-color-scheme:dark){:root{--ink:${INK.dark}}}</style>`);
fs.writeFileSync(out('assets/brand/favicon.svg'), favicon);
fs.writeFileSync(out('crates/owr-api/ui/favicon.svg'), favicon);

// Icon sprite: replace the brand symbols. Ink is currentColor; the accent is the UI's --accent.
// i-brand: full lockup (24 px type and up). i-brand-min: no atomic number, for the header bar.
const sprite = lockup({ ink: 'currentColor', accent: 'var(--accent, #2F6FEF)' });
const spriteMin = lockup({ ink: 'currentColor', accent: 'var(--accent, #2F6FEF)', withNumber: false });
const symbol = (id, vb, body) => `  <symbol id="${id}" viewBox="${vb}">\n    ${body}\n  </symbol>`;
const symbols = [
  symbol('i-brand', sprite.vb, sprite.body.join('\n    ')),
  symbol('i-brand-min', spriteMin.vb, spriteMin.body.join('\n    ')),
  symbol('i-brand-mark', '0 0 24 24', mark({ ink: 'currentColor', muted: 'currentColor', withNumber: false, stroke: 2 })),
].join('\n');
const iconsPath = out('crates/owr-api/ui/icons.svg');
let icons = fs.readFileSync(iconsPath, 'utf8');
icons = icons.replace(/\n  <symbol id="i-brand(-min|-mark)?"[\s\S]*?<\/symbol>/g, '');
icons = icons.replace(/\n<\/svg>\s*$/, `\n${symbols}\n</svg>\n`);
fs.writeFileSync(iconsPath, icons);

console.log(`lockup viewBox ${lk.vb} (aspect ${r3(lk.w / lk.h)}); min viewBox ${spriteMin.vb} (aspect ${r3(spriteMin.w / spriteMin.h)}); baseline-from-top ${r3(BASELINE_FROM_TOP)}em`);
console.log('wrote assets/brand/{lockup,lockup-light,lockup-dark,mark,mark-light,mark-dark,favicon}.svg, ui/favicon.svg, ui/icons.svg brand symbols');
