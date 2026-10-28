//! A minimal ZIP writer: STORED entries only (method 0, no
//! compression — a diagnostics bundle is mostly logs and
//! binaries that are either small or already compressed, and
//! v0.1 trades size for a writer simple enough to audit).
//! The output is an ordinary ZIP archive: local file headers,
//! an optional data descriptor after streamed entries (flag
//! bit 3), a central directory, and an end-of-central-
//! directory record. Sizes stay under the DiagKit bundle cap
//! (256 MiB), far below the 4 GiB point where ZIP64 would be
//! needed, so all size/offset fields are plain u32.
//!
//! `read_central_directory` is the matching reader for the
//! shapes this writer produces; the test suite uses it to
//! prove the archives are readable by the standard semantics
//! (walk the central directory, extract by the local header,
//! verify CRC-32), the same thing `unzip` does.

use std::io::{self, Read, Write};

use crate::hash::{Crc32, Sha256};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

const VERSION_NEEDED: u16 = 20;
const FLAG_UTF8: u16 = 0x0800;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const METHOD_STORED: u16 = 0;

/// One finished entry, as recorded in the central directory.
#[derive(Clone, Debug, PartialEq)]
pub struct WrittenEntry {
    pub name: String,
    pub size: u64,
    pub crc32: u32,
    pub sha256: String,
}

/// A counting writer so `bytes` in the result is the real
/// archive size without a second stat.
struct CountingWriter<W: Write> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct CentralRecord {
    name: String,
    size: u32,
    crc32: u32,
    flags: u16,
    local_offset: u32,
}

pub struct ZipWriter<W: Write> {
    out: CountingWriter<W>,
    records: Vec<CentralRecord>,
    /// DOS (date, time) stamped on every entry.
    dos_date: u16,
    dos_time: u16,
}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

impl<W: Write> ZipWriter<W> {
    pub fn new(inner: W, dos_date: u16, dos_time: u16) -> Self {
        ZipWriter {
            out: CountingWriter { inner, written: 0 },
            records: Vec::new(),
            dos_date,
            dos_time,
        }
    }

    fn local_header(&mut self, name: &str, flags: u16, crc: u32, size: u32) -> io::Result<u64> {
        let offset = self.out.written;
        let mut h = Vec::with_capacity(30 + name.len());
        put_u32(&mut h, LOCAL_SIG);
        put_u16(&mut h, VERSION_NEEDED);
        put_u16(&mut h, flags);
        put_u16(&mut h, METHOD_STORED);
        put_u16(&mut h, self.dos_time);
        put_u16(&mut h, self.dos_date);
        put_u32(&mut h, crc);
        put_u32(&mut h, size); // compressed == uncompressed (STORED)
        put_u32(&mut h, size);
        put_u16(&mut h, name.len() as u16);
        put_u16(&mut h, 0); // extra field length
        h.extend_from_slice(name.as_bytes());
        self.out.write_all(&h)?;
        Ok(offset)
    }

    /// Add an entry whose bytes are already in memory: CRC and
    /// size go straight into the local header (no descriptor).
    pub fn add_bytes(&mut self, name: &str, data: &[u8]) -> io::Result<WrittenEntry> {
        let crc = crate::hash::crc32(data);
        let sha = crate::hash::sha256_hex(data);
        let offset = self.local_header(name, FLAG_UTF8, crc, data.len() as u32)?;
        self.out.write_all(data)?;
        self.records.push(CentralRecord {
            name: name.to_string(),
            size: data.len() as u32,
            crc32: crc,
            flags: FLAG_UTF8,
            local_offset: offset as u32,
        });
        Ok(WrittenEntry {
            name: name.to_string(),
            size: data.len() as u64,
            crc32: crc,
            sha256: sha,
        })
    }

    /// Add an entry by streaming a reader: CRC-32 and SHA-256
    /// are computed as the bytes pass through, and the real
    /// values land in a trailing data descriptor plus the
    /// central directory (the local header carries zeros,
    /// flag bit 3). Memory stays flat however big the file
    /// is. Returns the entry as written (its size is the
    /// number of bytes actually read).
    pub fn add_reader<R: Read>(&mut self, name: &str, mut reader: R) -> io::Result<WrittenEntry> {
        let flags = FLAG_UTF8 | FLAG_DESCRIPTOR;
        let offset = self.local_header(name, flags, 0, 0)?;
        let mut crc = Crc32::new();
        let mut sha = Sha256::new();
        let mut size: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            crc.update(chunk);
            sha.update(chunk);
            self.out.write_all(chunk)?;
            size += n as u64;
        }
        let crc = crc.finalize();
        let mut d = Vec::with_capacity(16);
        put_u32(&mut d, DESCRIPTOR_SIG);
        put_u32(&mut d, crc);
        put_u32(&mut d, size as u32);
        put_u32(&mut d, size as u32);
        self.out.write_all(&d)?;
        self.records.push(CentralRecord {
            name: name.to_string(),
            size: size as u32,
            crc32: crc,
            flags,
            local_offset: offset as u32,
        });
        Ok(WrittenEntry {
            name: name.to_string(),
            size,
            crc32: crc,
            sha256: sha.finalize_hex(),
        })
    }

    /// Write the central directory + EOCD. Returns
    /// (entry count, total archive bytes).
    pub fn finish(mut self) -> io::Result<(usize, u64)> {
        let central_start = self.out.written;
        for r in &self.records {
            let mut h = Vec::with_capacity(46 + r.name.len());
            put_u32(&mut h, CENTRAL_SIG);
            put_u16(&mut h, VERSION_NEEDED); // version made by (low byte)
            put_u16(&mut h, VERSION_NEEDED);
            put_u16(&mut h, r.flags);
            put_u16(&mut h, METHOD_STORED);
            put_u16(&mut h, self.dos_time);
            put_u16(&mut h, self.dos_date);
            put_u32(&mut h, r.crc32);
            put_u32(&mut h, r.size);
            put_u32(&mut h, r.size);
            put_u16(&mut h, r.name.len() as u16);
            put_u16(&mut h, 0); // extra
            put_u16(&mut h, 0); // comment
            put_u16(&mut h, 0); // disk number start
            put_u16(&mut h, 0); // internal attributes
            put_u32(&mut h, 0); // external attributes
            put_u32(&mut h, r.local_offset);
            h.extend_from_slice(r.name.as_bytes());
            self.out.write_all(&h)?;
        }
        let central_size = self.out.written - central_start;
        let count = self.records.len();
        let mut e = Vec::with_capacity(22);
        put_u32(&mut e, EOCD_SIG);
        put_u16(&mut e, 0); // disk
        put_u16(&mut e, 0); // central directory disk
        put_u16(&mut e, count as u16);
        put_u16(&mut e, count as u16);
        put_u32(&mut e, central_size as u32);
        put_u32(&mut e, central_start as u32);
        put_u16(&mut e, 0); // comment length
        self.out.write_all(&e)?;
        self.out.flush()?;
        Ok((count, self.out.written))
    }
}

/// One entry read back from a central directory.
#[derive(Clone, Debug, PartialEq)]
pub struct CentralEntry {
    pub name: String,
    pub size: u64,
    pub crc32: u32,
    pub method: u16,
    pub local_offset: u64,
}

fn get_u16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn get_u32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse the central directory of a complete archive held in
/// memory (the verification reader: same walk `unzip` does).
pub fn read_central_directory(zip: &[u8]) -> Result<Vec<CentralEntry>, String> {
    if zip.len() < 22 {
        return Err("archive shorter than an EOCD record".to_string());
    }
    // EOCD is the last record; find its signature scanning
    // back from the end (comment length is 0 in our archives,
    // but scan anyway so a trailing comment cannot fool it).
    let mut eocd = None;
    let start = zip.len() - 22;
    let scan_from = start.saturating_sub(1024);
    let mut i = start;
    loop {
        if get_u32(zip, i) == Some(EOCD_SIG) {
            eocd = Some(i);
            break;
        }
        if i == scan_from {
            break;
        }
        i -= 1;
    }
    let eocd = eocd.ok_or("no end-of-central-directory record found")?;
    let count = get_u16(zip, eocd + 10).ok_or("truncated EOCD")? as usize;
    let mut pos = get_u32(zip, eocd + 16).ok_or("truncated EOCD")? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if get_u32(zip, pos) != Some(CENTRAL_SIG) {
            return Err(format!("bad central directory signature at byte {pos}"));
        }
        let method = get_u16(zip, pos + 10).ok_or("truncated central header")?;
        let crc = get_u32(zip, pos + 16).ok_or("truncated central header")?;
        let size = get_u32(zip, pos + 20).ok_or("truncated central header")? as u64;
        let name_len = get_u16(zip, pos + 28).ok_or("truncated central header")? as usize;
        let extra_len = get_u16(zip, pos + 30).ok_or("truncated central header")? as usize;
        let comment_len = get_u16(zip, pos + 32).ok_or("truncated central header")? as usize;
        let offset = get_u32(zip, pos + 42).ok_or("truncated central header")? as u64;
        let name_bytes = zip
            .get(pos + 46..pos + 46 + name_len)
            .ok_or("truncated central name")?;
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|_| "central directory name is not UTF-8".to_string())?;
        entries.push(CentralEntry {
            name,
            size,
            crc32: crc,
            method,
            local_offset: offset,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

/// Extract one entry's data using its central-directory
/// record: parse the local header at the recorded offset,
/// skip name + extra, then read `size` bytes (for entries
/// written with a data descriptor the local header's size
/// fields are zero — the central directory is the truth).
/// Returns the bytes; the caller verifies the CRC.
pub fn extract(zip: &[u8], entry: &CentralEntry) -> Result<Vec<u8>, String> {
    let pos = entry.local_offset as usize;
    if get_u32(zip, pos) != Some(LOCAL_SIG) {
        return Err(format!("bad local header signature at byte {pos}"));
    }
    let name_len = get_u16(zip, pos + 26).ok_or("truncated local header")? as usize;
    let extra_len = get_u16(zip, pos + 28).ok_or("truncated local header")? as usize;
    let data_start = pos + 30 + name_len + extra_len;
    let data_end = data_start + entry.size as usize;
    zip.get(data_start..data_end)
        .map(|s| s.to_vec())
        .ok_or_else(|| format!("entry \"{}\" data overruns the archive", entry.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // The writer owns its sink, so tests build into a Vec
    // through a reference-counted shared buffer.
    fn build_archive_shared() -> (Vec<u8>, Vec<WrittenEntry>) {
        #[derive(Clone)]
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buf = Shared(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let handle = buf.clone();
        let mut zw = ZipWriter::new(buf, 0x5821, 0x4000);
        let mut written = Vec::new();
        written.push(zw.add_bytes("notes.txt", b"hello diag").unwrap());
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        written.push(zw.add_reader("logs/big.log", Cursor::new(big)).unwrap());
        written.push(zw.add_bytes("empty.bin", b"").unwrap());
        let (count, bytes) = zw.finish().unwrap();
        assert_eq!(count, 3);
        let archive = handle.0.lock().unwrap().clone();
        assert_eq!(archive.len() as u64, bytes);
        (archive, written)
    }

    #[test]
    fn central_directory_round_trip_with_crc() {
        let (archive, written) = build_archive_shared();
        let central = read_central_directory(&archive).unwrap();
        assert_eq!(central.len(), 3);
        for (c, w) in central.iter().zip(written.iter()) {
            assert_eq!(c.name, w.name);
            assert_eq!(c.size, w.size);
            assert_eq!(c.method, METHOD_STORED);
            assert_eq!(c.crc32, w.crc32);
            // The unzip check: extract by the local header and
            // verify the stored CRC against the actual bytes.
            let data = extract(&archive, c).unwrap();
            assert_eq!(data.len() as u64, c.size);
            assert_eq!(
                crate::hash::crc32(&data),
                c.crc32,
                "CRC mismatch on {}",
                c.name
            );
            assert_eq!(crate::hash::sha256_hex(&data), w.sha256);
        }
        assert_eq!(extract(&archive, &central[0]).unwrap(), b"hello diag");
        assert_eq!(extract(&archive, &central[2]).unwrap(), b"");
    }

    #[test]
    fn streamed_entry_uses_descriptor_and_central_truth() {
        let (archive, written) = build_archive_shared();
        let central = read_central_directory(&archive).unwrap();
        let big = &central[1];
        assert_eq!(big.size, 200_000);
        // Local header of a streamed entry carries zeros +
        // flag bit 3; the descriptor follows the data.
        let pos = big.local_offset as usize;
        assert_eq!(
            get_u16(&archive, pos + 6).unwrap() & FLAG_DESCRIPTOR,
            FLAG_DESCRIPTOR
        );
        assert_eq!(get_u32(&archive, pos + 14).unwrap(), 0); // crc field
        let data = extract(&archive, big).unwrap();
        assert_eq!(data.len(), 200_000);
        let after = pos + 30 + "logs/big.log".len() + 200_000;
        assert_eq!(get_u32(&archive, after).unwrap(), DESCRIPTOR_SIG);
        assert_eq!(get_u32(&archive, after + 4).unwrap(), written[1].crc32);
    }

    #[test]
    fn reader_rejects_garbage() {
        assert!(read_central_directory(b"not a zip").is_err());
        assert!(read_central_directory(&[0u8; 100]).is_err());
    }
}
