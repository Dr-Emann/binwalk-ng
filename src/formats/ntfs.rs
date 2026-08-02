use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "NTFS partition";

/// NTFS partitions start with these bytes
pub fn ntfs_magic() -> Vec<Vec<u8>> {
    vec![b"\xEb\x52\x90NTFS\x20\x20\x20\x20".to_vec()]
}

/// Validates the NTFS header
pub fn ntfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(ntfs_header) = parse_ntfs_header(&file_data[offset..]) {
        // The reported sector count does not include the NTFS boot sector itself. Both fields come
        // from the header, so their product can overflow rather than simply being larger than the
        // file.
        let sector_size = ntfs_header.sector_size as usize;
        let Some(partition_size) = (ntfs_header.sector_count as usize)
            .checked_add(1)
            .and_then(|sectors| sectors.checked_mul(sector_size))
        else {
            return Err(SignatureError);
        };
        result.size = partition_size;

        // Simple sanity check on the reported total size
        if result.size > sector_size {
            result.description = format!(
                "{}, number of sectors: {}, bytes per sector: {}, total size: {} bytes",
                result.description, ntfs_header.sector_count, ntfs_header.sector_size, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store NTFS info
#[derive(Debug, Default, Clone)]
pub struct NTFSPartition {
    pub sector_size: u16,
    pub sector_count: u64,
}

// https://en.wikipedia.org/wiki/NTFS
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct NtfsPartitionHeader {
    opcodes: [u8; 3],
    magic: zerocopy::U64<LE>,
    bytes_per_sector: zerocopy::U16<LE>,
    sectors_per_cluster: u8,
    unused1: [u8; 7],
    media_type: u8,
    unused2: [u8; 2],
    sectors_per_track: zerocopy::U16<LE>,
    head_count: zerocopy::U16<LE>,
    hidden_sector_count: zerocopy::U32<LE>,
    unused3: [u8; 4],
    unknown: [u8; 4],
    sector_count: zerocopy::U64<LE>,
}

/// Parses an NTFS partition header
pub fn parse_ntfs_header(ntfs_data: &[u8]) -> Result<NTFSPartition, StructureError> {
    // Parse the NTFS partition header
    let (ntfs_header, _) =
        NtfsPartitionHeader::ref_from_prefix(ntfs_data).map_err(|_| StructureError)?;

    // Sanity check to make sure the unused fields are not used
    if ntfs_header
        .unused1
        .iter()
        .chain(&ntfs_header.unused2)
        .chain(&ntfs_header.unused3)
        .all(|&b| b == 0)
    {
        return Ok(NTFSPartition {
            sector_count: ntfs_header.sector_count.get(),
            sector_size: ntfs_header.bytes_per_sector.get(),
        });
    }

    Err(StructureError)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_SIZE: usize = 48;
    const SECTOR_SIZE_OFFSET: usize = 11;
    const SECTOR_COUNT_OFFSET: usize = 40;

    /// Builds an NTFS boot sector; every field besides these two stays zero, which is what the
    /// parser requires of the unused ones
    fn ntfs_header(sector_size: u16, sector_count: u64) -> Vec<u8> {
        let mut header = vec![0u8; HEADER_SIZE];
        header[0..11].copy_from_slice(b"\xEB\x52\x90NTFS\x20\x20\x20\x20");
        header[SECTOR_SIZE_OFFSET..SECTOR_SIZE_OFFSET + 2]
            .copy_from_slice(&sector_size.to_le_bytes());
        header[SECTOR_COUNT_OFFSET..SECTOR_COUNT_OFFSET + 8]
            .copy_from_slice(&sector_count.to_le_bytes());
        header
    }

    #[test]
    fn partition_size_that_overflows_is_rejected() {
        // The boot sector is added to the sector count before the multiply, so the addition and
        // the multiplication each need guarding; the first pair overflows the add, the second the
        // multiply
        for (sector_size, sector_count) in [(u16::MAX, u64::MAX), (u16::MAX, u64::MAX / 2)] {
            let header = ntfs_header(sector_size, sector_count);
            assert!(
                ntfs_parser(&header, 0).is_err(),
                "{sector_size} x {sector_count} should be rejected"
            );
        }
    }

    #[test]
    fn plausible_partition_is_accepted() {
        const SECTOR_SIZE: u16 = 512;
        const SECTOR_COUNT: u64 = 100;

        let header = ntfs_header(SECTOR_SIZE, SECTOR_COUNT);
        let result = ntfs_parser(&header, 0).expect("a sane partition should parse");

        // The reported count excludes the boot sector, so the size covers one sector more
        assert_eq!(
            result.size,
            SECTOR_SIZE as usize * (SECTOR_COUNT as usize + 1)
        );
    }
}
