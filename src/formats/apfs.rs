use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "APple File System";

/// APFS magic bytes
pub fn apfs_magic() -> Vec<Vec<u8>> {
    vec![b"NXSB".to_vec()]
}

/// Validates the APFS header
pub fn apfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MBR_BLOCK_SIZE: usize = 512;

    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if offset >= MAGIC_OFFSET {
        result.offset = offset - MAGIC_OFFSET;
        let available_data = file_data.len() - result.offset;

        if let Ok(apfs_header) = parse_apfs_header(&file_data[result.offset..]) {
            let mut truncated_message = "".to_string();

            // Both come from the header, so their product can overflow rather than simply being
            // larger than the file
            let Some(image_size) = apfs_header.block_count.checked_mul(apfs_header.block_size)
            else {
                return Err(SignatureError);
            };
            result.size = image_size;

            // It is observed that an APFS contained in an EFIGPT with a protective MBR includes the MBR block in its size.
            // If the APFS image is pulled out of the EFIGPT, the reported size will be 512 bytes too long, but otherwise valid.
            if result.size > available_data {
                let truncated_size = result.size - available_data;

                // If the calculated size is 512 bytes short, adjust the reported APFS size accordingly
                if truncated_size == MBR_BLOCK_SIZE {
                    result.size -= truncated_size;
                    truncated_message = format!(" (truncated by {truncated_size} bytes)");
                }
            }

            result.description = format!(
                "{}, block size: {} bytes, block count: {}, total size: {} bytes{}",
                result.description,
                apfs_header.block_size,
                apfs_header.block_count,
                result.size,
                truncated_message
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Offset of the APFS magic bytes from the start of the APFS image
pub const MAGIC_OFFSET: usize = 0x20;

/// Struct to store APFS header info
#[derive(Debug, Default, Clone)]
pub struct APFSHeader {
    pub block_size: usize,
    pub block_count: usize,
}

// Partial APFS header, just to figure out the size of the image and validate some fields
// https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct APFSHeaderBytes {
    magic: zerocopy::U32<LE>,
    block_size: zerocopy::U32<LE>,
    block_count: zerocopy::U64<LE>,
    nx_features: zerocopy::U64<LE>,
    nx_ro_compat_features: zerocopy::U64<LE>,
    nx_incompat_features: zerocopy::U64<LE>,
    nx_uuid_p1: zerocopy::U64<LE>,
    nx_uuid_p2: zerocopy::U64<LE>,
    nx_next_oid: zerocopy::U64<LE>,
    nx_next_xid: zerocopy::U64<LE>,
    nx_xp_desc_blocks: zerocopy::U32<LE>,
    nx_xp_data_blocks: zerocopy::U32<LE>,
    nx_xp_desc_base: zerocopy::U64<LE>,
    nx_xp_data_base: zerocopy::U64<LE>,
    nx_xp_desc_next: zerocopy::U32<LE>,
    nx_xp_data_next: zerocopy::U32<LE>,
    nx_xp_desc_index: zerocopy::U32<LE>,
    nx_xp_desc_len: zerocopy::U32<LE>,
    nx_xp_data_index: zerocopy::U32<LE>,
    nx_xp_data_len: zerocopy::U32<LE>,
    nx_spaceman_oid: zerocopy::U64<LE>,
    nx_omap_oid: zerocopy::U64<LE>,
    nx_reaper_oid: zerocopy::U64<LE>,
    nx_xp_test_type: zerocopy::U32<LE>,
    nx_xp_max_file_systems: zerocopy::U32<LE>,
}

/// Parses an APFS header
pub fn parse_apfs_header(apfs_data: &[u8]) -> Result<APFSHeader, StructureError> {
    const MAX_FS_COUNT: usize = 100;
    const FS_COUNT_BLOCK_SIZE: usize = 512;

    // Expected values of superblock flag fields
    let allowed_feature_flags = [0, 1, 2, 3];
    let allowed_incompat_flags = [0, 1, 2, 3, 0x100, 0x101, 0x102, 0x103];
    let allowed_ro_compat_flags = [0];

    let apfs_struct_start = MAGIC_OFFSET;
    let apfs_struct_end = apfs_struct_start + std::mem::size_of::<APFSHeaderBytes>();

    // Parse the header
    if let Some(apfs_structure_data) = apfs_data.get(apfs_struct_start..apfs_struct_end) {
        let (apfs_header, _) =
            APFSHeaderBytes::ref_from_prefix(apfs_structure_data).map_err(|_| StructureError)?;
        // Simple sanity check on the reported block data
        if apfs_header.block_size.get() != 0 && apfs_header.block_count.get() != 0 {
            // Sanity check the feature flags
            if allowed_feature_flags.contains(&apfs_header.nx_features.get())
                && allowed_ro_compat_flags.contains(&apfs_header.nx_ro_compat_features.get())
                && allowed_incompat_flags.contains(&apfs_header.nx_incompat_features.get())
            {
                // The test_type field *must* be NULL
                if apfs_header.nx_xp_test_type == 0 {
                    // Calculate the file system count; this is max_file_systems divided by 512, rounded up to nearest whole
                    let fs_count = ((apfs_header.nx_xp_max_file_systems.get() as f32)
                        / (FS_COUNT_BLOCK_SIZE as f32))
                        .ceil() as usize;

                    // Sanity check the file system count
                    if fs_count > 0 && fs_count <= MAX_FS_COUNT {
                        return Ok(APFSHeader {
                            block_size: apfs_header.block_size.get() as usize,
                            block_count: apfs_header.block_count.get() as usize,
                        });
                    }
                }
            }
        }
    }

    Err(StructureError)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK_SIZE_OFFSET: usize = MAGIC_OFFSET + 4;
    const BLOCK_COUNT_OFFSET: usize = MAGIC_OFFSET + 8;
    const MAX_FILE_SYSTEMS_OFFSET: usize = MAGIC_OFFSET + 148;

    /// Builds an APFS superblock. Every field the parser sanity checks besides these two is left
    /// zero, which is the accepted value for all of them except the file system count.
    fn apfs_image(block_size: u32, block_count: u64) -> Vec<u8> {
        // Divided by 512 and rounded up, this has to land between 1 and 100
        const MAX_FILE_SYSTEMS: u32 = 512;

        let mut image = vec![0u8; MAGIC_OFFSET + std::mem::size_of::<APFSHeaderBytes>()];
        image[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(b"NXSB");
        image[BLOCK_SIZE_OFFSET..BLOCK_SIZE_OFFSET + 4].copy_from_slice(&block_size.to_le_bytes());
        image[BLOCK_COUNT_OFFSET..BLOCK_COUNT_OFFSET + 8]
            .copy_from_slice(&block_count.to_le_bytes());
        image[MAX_FILE_SYSTEMS_OFFSET..MAX_FILE_SYSTEMS_OFFSET + 4]
            .copy_from_slice(&MAX_FILE_SYSTEMS.to_le_bytes());
        image
    }

    #[test]
    fn image_size_that_overflows_is_rejected() {
        let image = apfs_image(u32::MAX, u64::MAX);
        assert!(apfs_parser(&image, MAGIC_OFFSET).is_err());
    }

    #[test]
    fn plausible_image_is_accepted() {
        const BLOCK_SIZE: u32 = 4096;
        const BLOCK_COUNT: u64 = 10;

        let image = apfs_image(BLOCK_SIZE, BLOCK_COUNT);
        let result = apfs_parser(&image, MAGIC_OFFSET).expect("a sane superblock should parse");

        assert_eq!(result.offset, 0);
        assert_eq!(result.size, BLOCK_SIZE as usize * BLOCK_COUNT as usize);
    }
}
