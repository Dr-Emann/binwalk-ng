use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use bzip2::read::BzDecoder;
use std::io;
use std::io::Read;

/// Human readable description
pub const DESCRIPTION: &str = "bzip2 compressed data";

/// Bzip2 magic bytes; includes the magic bytes, version number, block size, and compressed magic signature
pub fn bzip2_magic() -> Vec<Vec<u8>> {
    vec![
        b"BZh91AY&SY".to_vec(),
        b"BZh81AY&SY".to_vec(),
        b"BZh71AY&SY".to_vec(),
        b"BZh61AY&SY".to_vec(),
        b"BZh51AY&SY".to_vec(),
        b"BZh41AY&SY".to_vec(),
        b"BZh31AY&SY".to_vec(),
        b"BZh21AY&SY".to_vec(),
        b"BZh11AY&SY".to_vec(),
    ]
}

/// Bzip2 header parser
pub fn bzip2_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let dry_run_sig = SignatureResult {
        offset,
        ..Default::default()
    };
    let dry_run =
        bzip2_decompressor(file_data, &dry_run_sig, &Chroot::dry_run()).unwrap_or_default();

    if dry_run.success
        && let Some(bzip2_size) = dry_run.size
    {
        result.size = bzip2_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Defines the internal extractor function for decompressing BZIP2 files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::bzip2::bzip2_extractor;
///
/// match bzip2_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn bzip2_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(bzip2_decompressor),
        ..Default::default()
    }
}

/// Internal extractor for decompressing BZIP2 data
pub fn bzip2_decompressor(
    file_data: &[u8],
    signature: &SignatureResult,
    chroot: &Chroot,
) -> io::Result<ExtractionResult> {
    // Output file for decompressed data
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";

    let offset = signature.offset;
    let mut result = ExtractionResult::default();

    // Slice the data starting from the provided offset
    let bzip2_data = &file_data[offset..];

    let mut decoder = BzDecoder::new(bzip2_data);

    // Decompress the entire stream; reading it in full both validates the stream and lets
    // total_in() report exactly how many compressed bytes were consumed. The decompressed
    // data is written via the chroot, which is a no-op for a dry-run chroot.
    let mut decompressed_output = Vec::new();
    if decoder.read_to_end(&mut decompressed_output).is_ok()
        && chroot.create_file(OUTPUT_FILE_NAME, &decompressed_output)
    {
        result.success = true;
        // total_in() tells us exactly how many compressed bytes were read from file_data
        result.size = Some(decoder.total_in() as usize);
    }

    Ok(result)
}
