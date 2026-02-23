use std::ffi::OsString;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use binrw::BinRead;
use chrono::{DateTime, Utc};

use hdk_archive::bar::structs::BarArchive;
use hdk_archive::sharc::builder::SharcBuilder;
use hdk_archive::sharc::structs::SharcArchive;
use hdk_archive::structs::{
    ARCHIVE_MAGIC, ArchiveFlags, ArchiveFlagsValue, CompressionType, Endianness,
};
use hdk_sdat::{SdatKeys, SdatReader, SdatWriter};
use hdk_secure::hash::AfsHash;
use rand::RngExt;

// Encrypts the header and the entries.
// Used for SHARC archives embedded in SDAT files.
const SHARC_SDAT_KEY: [u8; 32] = [
    0xF1, 0xBF, 0x6A, 0x4F, 0xBB, 0xBA, 0x5D, 0x0E, 0xD2, 0x7F, 0x41, 0x8A, 0x48, 0x88, 0xAF, 0x30,
    0x47, 0x86, 0xEC, 0xD4, 0x4E, 0x2D, 0x36, 0x46, 0x80, 0xDB, 0x4D, 0xF2, 0x22, 0x3A, 0x9F, 0x56,
];

/// DEFAULT key used to encrypt BAR file bodies.
/// Used in BAR archives.
const BAR_DEFAULT_KEY: [u8; 32] = [
    0x80, 0x6D, 0x79, 0x16, 0x23, 0x42, 0xA1, 0x0E, 0x8F, 0x78, 0x14, 0xD4, 0xF9, 0x94, 0xA2, 0xD1,
    0x74, 0x13, 0xFC, 0xA8, 0xF6, 0xE0, 0xB8, 0xA4, 0xED, 0xB9, 0xDC, 0x32, 0x7F, 0x8B, 0xA7, 0x11,
];

/// Signature key used to encrypt BAR file head/signature area.
/// Used in BAR archives.
const BAR_SIGNATURE_KEY: [u8; 32] = [
    0xEF, 0x8C, 0x7D, 0xE8, 0xE5, 0xD5, 0xD6, 0x1D, 0x6A, 0xAA, 0x5A, 0xCA, 0xF7, 0xC1, 0x6F, 0xC4,
    0x5A, 0xFC, 0x59, 0xE4, 0x8F, 0xE6, 0xC5, 0x93, 0x7E, 0xBD, 0xFF, 0xC1, 0xE3, 0x99, 0x9E, 0x62,
];

/// Cryptographic keys used for SDAT decryption.
const SDAT_KEYS: hdk_sdat::SdatKeys = hdk_sdat::SdatKeys {
    sdat_key: [
        0x0D, 0x65, 0x5E, 0xF8, 0xE6, 0x74, 0xA9, 0x8A, 0xB8, 0x50, 0x5C, 0xFA, 0x7D, 0x01, 0x29,
        0x33,
    ],
    edat_hash_0: [
        0xEF, 0xFE, 0x5B, 0xD1, 0x65, 0x2E, 0xEB, 0xC1, 0x19, 0x18, 0xCF, 0x7C, 0x04, 0xD4, 0xF0,
        0x11,
    ],
    edat_hash_1: [
        0x3D, 0x92, 0x69, 0x9B, 0x70, 0x5B, 0x07, 0x38, 0x54, 0xD8, 0xFC, 0xC6, 0xC7, 0x67, 0x27,
        0x47,
    ],
    edat_key_0: [
        0xBE, 0x95, 0x9C, 0xA8, 0x30, 0x8D, 0xEF, 0xA2, 0xE5, 0xE1, 0x80, 0xC6, 0x37, 0x12, 0xA9,
        0xAE,
    ],
    edat_key_1: [
        0x4C, 0xA9, 0xC1, 0x4B, 0x01, 0xC9, 0x53, 0x09, 0x96, 0x9B, 0xEC, 0x68, 0xAA, 0x0B, 0xC0,
        0x81,
    ],
    npdrm_omac_key_2: [
        0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25,
        0x6B,
    ],
    npdrm_omac_key_3: [
        0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E,
        0x97,
    ],
};

/// Files key to encrypt files with in SHARC
const SHARC_FILES_KEY: [u8; 16] = *b"hdk_resharc_file";

/// Any file in here will not be included in the repacked SHARC.
#[allow(overflowing_literals)]
const BAD_FILES: [AfsHash; 2] = [AfsHash(0xD3A7AF9F_i32), AfsHash(0xEDFBFAE9_i32)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Bar,
    Sharc,
}

#[derive(Debug, Clone)]
struct ExtractedEntry {
    name_hash: hdk_secure::hash::AfsHash,
    compression: CompressionType,
    extracted_path: PathBuf,
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "Usage: sdat-normalizer <file1.sdat> [file2.sdat ...]\n\
Drag-and-drop a .sdat file onto this .exe on Windows.\n"
        );
        std::process::exit(1);
    }

    for arg in args {
        let path = PathBuf::from(arg);
        normalize_one(&path, &SDAT_KEYS)
            .with_context(|| format!("failed to normalize {}", path.display()))?;
    }

    Ok(())
}

fn normalize_one(input_sdat_path: &Path, sdat_keys: &SdatKeys) -> Result<()> {
    if !input_sdat_path.exists() {
        bail!("input does not exist: {}", input_sdat_path.display());
    }
    if input_sdat_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("sdat"))
        != Some(true)
    {
        bail!("expected .sdat file, got: {}", input_sdat_path.display());
    }

    let input_bytes =
        fs::read(input_sdat_path).with_context(|| format!("read {}", input_sdat_path.display()))?;

    // 1) SDAT -> raw archive bytes
    let mut r = SdatReader::open(Cursor::new(input_bytes), sdat_keys)
        .context("open SDAT (check your SDAT keys)")?;
    let archive_bytes = r.decrypt_to_vec().context("decrypt SDAT payload")?;

    // 2) Detect archive type + endian
    let (archive_kind, endianness) = detect_archive(&archive_bytes)?;

    // 3) Unpack archive entries to a temp dir
    let temp = tempfile::tempdir().context("create tempdir")?;
    let extract_root = temp.path().join("extracted");
    fs::create_dir_all(&extract_root).context("create extracted dir")?;

    let mut extracted =
        extract_archive_to_dir(&archive_bytes, archive_kind, endianness, &extract_root)
            .context("extract archive")?;

    // 4) Repack extracted files into a SHARC archive
    let (sharc_bytes, sharc_timestamp) =
        repack_to_sharc(&mut extracted, endianness).context("repack to SHARC")?;

    // 5) Repack SHARC -> SDAT
    let output_name = input_sdat_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("OUTPUT.SDAT");
    let writer = SdatWriter::new(output_name, *sdat_keys).context("init SDAT writer")?;
    let out_sdat_bytes = writer.write_to_vec(&sharc_bytes).context("write SDAT")?;

    let output_path = normalized_output_path(input_sdat_path);
    fs::write(&output_path, out_sdat_bytes)
        .with_context(|| format!("write {}", output_path.display()))?;

    let txt_path = normalized_txt_path(input_sdat_path);
    let txt = sharc_timestamp
        .to_be_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("");
    fs::write(&txt_path, format!("{txt}\n"))
        .with_context(|| format!("write {}", txt_path.display()))?;

    println!(
        "OK: {} -> {}",
        input_sdat_path.display(),
        output_path.display()
    );
    Ok(())
}

fn normalized_output_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    parent.join(format!("{stem}.normalized.sdat"))
}

fn normalized_txt_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    parent.join(format!("{stem}.normalized.txt"))
}

fn detect_archive(bytes: &[u8]) -> Result<(ArchiveKind, Endianness)> {
    if bytes.len() < 8 {
        bail!("archive payload too small ({})", bytes.len());
    }

    let magic_le = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().unwrap());

    let (endianness, ver_flags) = if magic_le == ARCHIVE_MAGIC {
        (
            Endianness::Little,
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        )
    } else if magic_be == ARCHIVE_MAGIC {
        (
            Endianness::Big,
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        )
    } else {
        bail!("not a BAR/SHARC archive (bad magic)");
    };

    let version = (ver_flags >> 16) as u16;
    let kind = match version {
        256 => ArchiveKind::Bar,
        512 => ArchiveKind::Sharc,
        _ => bail!("unsupported archive version {version}"),
    };

    Ok((kind, endianness))
}

fn extract_archive_to_dir(
    archive_bytes: &[u8],
    kind: ArchiveKind,
    endianness: Endianness,
    out_dir: &Path,
) -> Result<Vec<ExtractedEntry>> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(archive_bytes);

    match kind {
        ArchiveKind::Bar => {
            let reader = match endianness {
                Endianness::Little => BarArchive::read_le_args(
                    &mut cursor,
                    (
                        BAR_DEFAULT_KEY,
                        BAR_SIGNATURE_KEY,
                        archive_bytes.len() as u32,
                    ),
                ),
                Endianness::Big => BarArchive::read_be_args(
                    &mut cursor,
                    (
                        BAR_DEFAULT_KEY,
                        BAR_SIGNATURE_KEY,
                        archive_bytes.len() as u32,
                    ),
                ),
            }
            .context("open BAR")?;

            for entry in &reader.entries {
                let data = reader
                    .entry_data(&mut cursor, entry, &BAR_DEFAULT_KEY, &BAR_SIGNATURE_KEY)
                    .context("read BAR entry data")?;

                let file_name = entry.name_hash.to_string();
                let extracted_path = out_dir.join(file_name);
                fs::write(&extracted_path, &data).context("write extracted file")?;

                out.push(ExtractedEntry {
                    name_hash: entry.name_hash,
                    compression: entry.location.1,
                    extracted_path,
                });
            }
        }

        ArchiveKind::Sharc => {
            // Prefer the SDAT-embedded key first, then fall back to the core key.
            let reader = match endianness {
                Endianness::Little => SharcArchive::read_le_args(
                    &mut cursor,
                    (SHARC_SDAT_KEY, archive_bytes.len() as u32),
                ),
                Endianness::Big => SharcArchive::read_be_args(
                    &mut cursor,
                    (SHARC_SDAT_KEY, archive_bytes.len() as u32),
                ),
            }
            .context("open SHARC with SDAT key")?;

            for entry in &reader.entries {
                let data = reader.entry_data(&mut cursor, entry)?;

                let file_name = entry.name_hash.to_string();
                let extracted_path = out_dir.join(file_name);
                fs::write(&extracted_path, &data).context("write extracted file")?;

                let compression =
                    CompressionType::try_from(entry.location.1).unwrap_or(CompressionType::None);

                out.push(ExtractedEntry {
                    name_hash: entry.name_hash,
                    compression,
                    extracted_path,
                });
            }
        }
    }

    Ok(out)
}

fn repack_to_sharc(
    extracted: &mut [ExtractedEntry],
    endianness: Endianness,
) -> Result<(Vec<u8>, i32)> {
    let timestamp = chrono::Utc::now().timestamp() as i32;

    let mut w = SharcBuilder::new(SHARC_SDAT_KEY, SHARC_FILES_KEY)
        .with_flags(ArchiveFlags(ArchiveFlagsValue::Protected.into()))
        .with_timestamp(timestamp);

    // Sort entries by name hash to ensure consistent ordering.
    extracted.sort_by_key(|e| e.name_hash.0);

    for entry in extracted {
        if BAD_FILES.contains(&entry.name_hash) {
            println!(
                "Skipping file with hash {} ({}), not including in repacked SHARC",
                entry.name_hash,
                entry.extracted_path.display()
            );

            continue;
        }

        let data = std::fs::read(&entry.extracted_path)
            .with_context(|| format!("read extracted file {}", entry.extracted_path.display()))?;

        let mut iv: [u8; 8] = [0; 8];
        let mut rng = rand::rng();
        rng.fill(&mut iv);

        w.add_entry(entry.name_hash, data, entry.compression, iv);
    }

    println!(
        "New SHARC timestamp: {:X} ({})",
        timestamp,
        DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "invalid timestamp".to_string())
    );

    let mut writer = Cursor::new(Vec::<u8>::new());

    w.build(&mut writer, endianness.into())
        .context("finish SHARC")?;

    Ok((writer.into_inner(), timestamp))
}
