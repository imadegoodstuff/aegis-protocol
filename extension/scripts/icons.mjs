// Writes the extension icons: a hexagonal shield on a dark field, no
// dependencies (raw PNG encoder). Run: node scripts/icons.mjs
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, crc]); };

function png(size, pixel) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x + 0.5, y + 0.5);
      raw.set([r, g, b, a], y * (size * 4 + 1) + 1 + x * 4);
    }
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// Signed distance to a regular hexagon (pointy top) of circumradius R centred at c.
function hexDist(x, y, c, R) {
  const px = Math.abs(x - c), py = Math.abs(y - c);
  const k = [-0.8660254, 0.5, 0.57735];
  let qx = px, qy = py;
  const d = 2 * Math.min(k[0] * qx + k[1] * qy, 0);
  qx -= d * k[0]; qy -= d * k[1];
  const r = R * 0.8660254;
  const cx = Math.min(Math.max(qx, -k[2] * r), k[2] * r);
  const dx = qx - cx, dy = qy - r;
  return Math.hypot(dx, dy) * Math.sign(dy);
}

const smooth = (d, w = 1) => Math.min(1, Math.max(0, 0.5 - d / w));

for (const size of [16, 48, 128]) {
  const c = size / 2;
  const R = size * 0.42;
  const stroke = Math.max(1, size * 0.06);
  const buf = png(size, (x, y) => {
    // dark rounded square field
    const m = size * 0.08, rr = size * 0.22;
    const qx = Math.max(Math.abs(x - c) - (c - m - rr), 0), qy = Math.max(Math.abs(y - c) - (c - m - rr), 0);
    const field = smooth(Math.hypot(qx, qy) - rr);
    let r = 11, g = 16, b = 32, a = field;
    // hexagon outline, electric cyan
    const d = hexDist(x, y, c, R);
    const ring = smooth(Math.abs(d) - stroke / 2);
    // root node at the centre
    const node = smooth(Math.hypot(x - c, y - c) - size * 0.09);
    const t = Math.max(ring, node);
    r = r * (1 - t) + 80 * t; g = g * (1 - t) + 200 * t; b = b * (1 - t) + 255 * t;
    a = Math.max(a, t);
    return [Math.round(r), Math.round(g), Math.round(b), Math.round(a * 255)];
  });
  mkdirSync(new URL("../public/icons/", import.meta.url), { recursive: true });
  writeFileSync(new URL(`../public/icons/${size}.png`, import.meta.url), buf);
  console.log(`icons/${size}.png`);
}
