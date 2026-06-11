//! # File Extractors
//!
//! File extractors may be internal (written in Rust, compiled into Binwalk), or external (command line utilties).
//!
//! While the former are generally faster, safer, and portable, the latter requires very little code to implement.
//!
//! Binwalk relies on various internal and external utilities for automated file extraction.
//!
//! ## External Extractors
//!
//! To implement an external extractor, you must use the `extractors::Extractor` struct to define:
//!
//! - The name of a command-line utility to run
//! - What arguments to pass to it
//! - What file extension the utility expects
//! - Which exit codes are considered successful (the default is exit code `0`)
//!
//! ### Example
//!
//! We want to define an external extractor for a new, contrived, file type, `FooBar`. A command-line utility,
//! `unfoobar`, exists, and is typically executed as such:
//!
//! ```bash
//! unfoobar -x -f input_file.bin -o data.foobar
//! ```
//!
//! To define this external utility as an extractor:
//!
//! ```no_run
//! use binwalk_ng::extractors::{Extractor, ExtractorType, SOURCE_FILE_PLACEHOLDER};
//!
//! /// This function returns an instance of extractors::Extractor, which describes how to run the unfoobar utility.
//! pub fn foobar_extractor() -> Extractor {
//!    // Build and return the Extractor struct
//!    return Extractor {
//!        // This indicates that we are defining an external extractor, named 'unfoobar'
//!        utility: ExtractorType::External("unfoobar".to_string()),
//!        // This is the file extension to use when carving the FooBar file system data to disk
//!        extension: "bin".to_string(),
//!        // These are the arguments to pass to the unfoobar utility
//!        arguments: vec![
//!            "-x".to_string(),           // This argument tells unfoobar to extract the FooBar data
//!            "-o".to_string(),           // Specify an output file
//!            "data.foobar".to_string(),  // The output file name
//!            "-f".to_string(),           // Specify an input file
//!            // This is a special string that will be replaced at run-time with the name of the source file
//!            SOURCE_FILE_PLACEHOLDER.to_string()
//!        ],
//!        // The only valid exit code for this utility is 0
//!        exit_codes: vec![0],
//!        // If set to true, the extracted files will not be analyzed
//!        do_not_recurse: false,
//!        ..Default::default()
//!    };
//! }
//! ```
//!
//! ## Internal Extractors
//!
//! Internal extractors are functions that are repsonsible for extracting the data of a particular file type.
//! They must conform to the `extractors::InternalExtractor` type definition.
//!
//! Like external extractors, they are defined using the `extractors::Extractor` struct.
//!
//! The internal extraction function will be passed:
//!
//! - The entirety of the file data
//! - An offset inside the file data at which to begin processing data
//! - An output directory for extracted files (optional)
//!
//! If the output directory is `None`, the extractor function should perform a "dry run", processing the intended file format
//! as normal, but must not extract any data; this allows signatures to use the extractor function to validate potential signature
//! matches without performing an actual extraction.
//!
//! Internal extractors must return an `extractors::ExtractionResult` struct.
//!
//! Internal extractors should use the `extractors::Chroot` API to write files to disk.
//! The methods defined in the `Chroot` struct allow the manipulation of files on disk while ensuring that any file paths
//! accessed do not traverse outside the specified output directory.
//!
//! ### Example
//!
//! ```ignore
//! use binwalk_ng::common::crc32;
//! use binwalk_ng::extractors::{Chroot, Extractor, ExtractionResult, ExtractorType};
//! use binwalk_ng::structures::foobar::parse_foobar_header;
//!
//! /// This function *defines* an internal extractor; it is not the actual extractor
//! pub fn foobar_extractor() -> Extractor {
//!    // Build and return the Extractor struct
//!     return Extractor {
//!         // This specifies the function extract_foobar_file as the internal extractor to use
//!         utility: ExtractorType::Internal(extract_foobar_file),
//!         ..Default::default()
//!     };
//! }
//!
//! /// This function extracts the contents of a FooBar file
//! pub fn extract_foobar_file(file_data: Vec<u8>, offset: usize, output_directory: Option<&Path>) -> ExtractionResult {
//!
//!     // This will be the return value
//!     let mut result = ExtractionResult::default();
//!
//!     // Get the FooBar file data, which starts at the specified offset
//!     if let Some(foobar_data) = file_data.get(offset..) {
//!         // Parse and validate the FooBar file header; this function is defined in the structures module
//!         if let Ok(foobar_header) = parse_foobar_header(foobar_data) {
//!             // Data CRC is calculated over data_size bytes, starting at the end of the FooBar header
//!             let crc_start = foobar_header.header_size;
//!             let crc_end = crc_start + foobar_header.data_size;
//!
//!             if let Some(crc_data) = foobar_data.get(crc_start..crc_end){
//!                 // Validate the data CRC
//!                 if foobar_header.data_crc == (crc32(crc_data) as usize) {
//!                     // Report the total size of the FooBar file, including header and data
//!                     result.size = Some(foobar_header.header_size + foobar_header.data_size);
//!
//!                     // If an output directory was specified, extract the contents of the FooBar file to disk
//!                     if let Some(output_directory) = output_directory {
//!                         // Chroot file I/O inside the specified output directory
//!                         let chroot = Chroot::new(output_directory);
//!
//!                         // The FooBar file format is very simple: just a header, followed by the data we want to extract.
//!                         // Carve the FooBar data to disk, and set result.success to true if this succeeds.
//!                         result.success = chroot.carve_file(foobar_header.original_file_name,
//!                                                            foobar_data,
//!                                                            foobar_header.header_size,
//!                                                            foobar_header.data_size);
//!                     } else {
//!                         // Nothing else to do, consider this a success
//!                         result.success = true;
//!                     }
//!                 }
//!             }
//!         }
//!     }
//!
//!     return result;
//! }
//! ```

use crate::signatures::SignatureResult;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs as unix_fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows;
use std::path::Path;
use std::path::{self, Component, PathBuf};
use std::process;
use walkdir::WalkDir;

/// This constants in command line arguments will be replaced with the path to the input file
pub const SOURCE_FILE_PLACEHOLDER: &str = "%e";

/// Return value of InternalExtractor upon error
#[derive(Debug, Clone)]
pub struct ExtractionError;

/// Built-in internal extractors must provide a function conforming to this definition.
/// Arguments: file_data, offset, output_directory.
pub type InternalExtractor = fn(&[u8], usize, Option<&Path>) -> ExtractionResult;

/// Enum to define either an Internal or External extractor type
#[derive(Debug, Default, Clone)]
pub enum ExtractorType {
    External(String),
    Internal(InternalExtractor),
    #[default]
    None,
}

/// Describes extractors, both external and internal
#[derive(Debug, Clone, Default)]
pub struct Extractor {
    /// External command or internal function to execute
    pub utility: ExtractorType,
    /// File extension expected by an external command
    pub extension: String,
    /// Arguments to pass to the external command
    pub arguments: Vec<String>,
    /// A list of successful exit codes for the external command
    pub exit_codes: Vec<i32>,
    /// Set to true to disable recursion into this extractor's extracted files
    pub do_not_recurse: bool,
}

/// Stores information about a completed extraction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionResult {
    /// Size of the data consumed during extraction, if known; should be populated by the constructor
    pub size: Option<usize>,
    /// Extractor success status; should be populated by the constructor
    pub success: bool,
    /// Extractor name, automatically populated by extractors::execute
    pub extractor: String,
    /// Set to true to disable recursion into this extractor's extracted files.
    /// Automatically populated with the corresponding Extractor.do_not_recurse field by extractors::execute.
    pub do_not_recurse: bool,
    /// The output directory where the extractor dropped its files, automatically populated by extractors::execute
    pub output_directory: PathBuf,
}

/// Stores information about external extractor processes. For internal use only.
#[derive(Debug)]
pub struct ProcInfo {
    pub child: process::Child,
    pub exit_codes: Vec<i32>,
    pub carved_file: String,
}

/// Provides chroot-like functionality for internal extractors
#[derive(Debug, Clone)]
pub struct Chroot {
    /// The chroot directory passed to Chroot::new
    pub chroot_directory: PathBuf,
}

impl Chroot {
    /// Create a new chrooted instance. All file paths will be effectively chrooted in the specified directory path.
    /// The chroot directory path will be created if it does not already exist.
    ///
    /// If no directory path is specified, the chroot directory will be `/`.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// // `chroot_directory` is stored in canonical (symlink-resolved) form.
    /// assert_eq!(chroot.chroot_directory, std::fs::canonicalize(&chroot_dir).unwrap());
    /// assert_eq!(std::path::Path::new(&chroot_dir).exists(), true);
    /// ```
    pub fn new(chroot_directory: impl AsRef<Path>) -> Self {
        let mut chroot_instance = Self::default();

        let chroot_directory = chroot_directory.as_ref();

        // Attempt to ensure that the specified path is absolute. If this fails, just use the path as given.
        match path::absolute(chroot_directory) {
            Ok(pathbuf) => {
                chroot_instance.chroot_directory = pathbuf;
            }
            Err(_) => {
                chroot_instance.chroot_directory = chroot_directory.to_path_buf();
            }
        }

        // Create the chroot directory if it does not exist
        if !path::Path::new(&chroot_instance.chroot_directory).exists() {
            match fs::create_dir_all(&chroot_instance.chroot_directory) {
                Ok(_) => {
                    debug!(
                        "Created new chroot directory {}",
                        chroot_instance.chroot_directory.display()
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to create chroot directory {}: {}",
                        chroot_instance.chroot_directory.display(),
                        e
                    );
                }
            }
        }

        // Now that the directory exists, store its canonical (fully symlink-resolved)
        // path. All later containment checks compare resolved paths against this, so the
        // chroot root must itself be canonical to be robust against symlinked prefixes
        // (e.g. macOS temp dirs under `/var -> /private/var`). If canonicalization fails,
        // keep the absolute path as-is.
        if let Ok(canonical) = fs::canonicalize(&chroot_instance.chroot_directory) {
            chroot_instance.chroot_directory = canonical;
        }

        chroot_instance
    }

    /// Joins two paths, ensuring that the final path does not traverse outside of the chroot directory.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    /// use std::path::{Path, PathBuf};
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// let dir_name = "etc";
    /// let abs_path_dir = Path::new("/").join(dir_name);
    /// let file_name = "passwd";
    /// let abs_path = abs_path_dir.join(file_name);
    /// let rel_path_dir: PathBuf = ["..", "..", "..", dir_name].iter().collect();
    /// let abs_path_file = Path::new("/").join(file_name);
    /// let rel_path_file: PathBuf = ["..", "..", "..", file_name].iter().collect();
    ///
    /// let path1 = chroot.safe_path_join(&abs_path_dir, file_name);
    /// let expected_path1 = chroot_dir.join(dir_name).join(file_name);
    ///
    /// let path2 = chroot.safe_path_join(&abs_path_dir, &rel_path_file);
    /// let expected_path2 = chroot_dir.join(file_name);
    ///
    /// let path3 = chroot.safe_path_join(&rel_path_dir, &abs_path_file);
    /// let expected_path3 = chroot_dir.join(dir_name).join(file_name);
    ///
    /// let path4 = chroot.safe_path_join(&chroot_dir, &abs_path);
    /// let expected_path4 = chroot_dir.join(dir_name).join(file_name);
    ///
    /// assert_eq!(path1, expected_path1);
    /// assert_eq!(path2, expected_path2);
    /// assert_eq!(path3, expected_path3);
    /// assert_eq!(path4, expected_path4);
    /// ```
    pub fn safe_path_join(&self, path1: impl AsRef<Path>, path2: impl AsRef<Path>) -> PathBuf {
        // Join and sanitize both paths; retain the leading '/' (if there is one)
        let path1 = path1.as_ref();
        let path2 = path2.as_ref();
        let path2 = path2.strip_prefix("/").unwrap_or(path2);

        let mut joined_path = self.sanitize_path(path1.join(path2));

        // If the joined path does not start with the chroot directory,
        // prepend the chroot directory to the final joined path.
        // on Windows: If no chroot directory is specified, skip the operation
        if cfg!(windows) && self.chroot_directory == path::MAIN_SEPARATOR.to_string() {
            // do nothing and skip
        } else if !joined_path.starts_with(&self.chroot_directory) {
            joined_path = self
                .chroot_directory
                .join(joined_path.strip_prefix("/").unwrap_or(&joined_path));
        }

        joined_path
    }

    /// Given a file path, returns a sanitized path that is chrooted inside the specified chroot directory.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let file_name = "test.txt";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    /// let path = chroot.chrooted_path(file_name);
    ///
    /// assert_eq!(path, std::path::Path::new(&chroot_dir).join(file_name).display().to_string());
    /// ```
    pub fn chrooted_path(&self, file_path: impl AsRef<Path>) -> PathBuf {
        self.safe_path_join(file_path, "")
    }

    /// Creates a regular file in the chrooted directory and writes the provided data to it.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_213_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let file_data: &[u8] = b"foobar";
    ///
    /// let file_name = "created_file.txt";
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_file(file_name, file_data), true);
    /// assert_eq!(std::fs::read_to_string(chroot_dir.join(file_name))?, std::str::from_utf8(file_data)?);
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_213_0(); }
    /// ```
    pub fn create_file(&self, file_path: impl AsRef<Path>, file_data: &[u8]) -> bool {
        let safe_file_path: PathBuf = match self.resolve_in_chroot(&file_path, true) {
            Some(path) => path,
            None => {
                error!(
                    "Refusing to create file {}: path escapes the chroot via a symlink",
                    file_path.as_ref().display()
                );
                return false;
            }
        };

        if !path::Path::new(&safe_file_path).exists() {
            match fs::write(safe_file_path.clone(), file_data) {
                Ok(_) => {
                    return true;
                }
                Err(e) => {
                    error!("Failed to write data to {}: {e}", safe_file_path.display());
                }
            }
        } else {
            error!(
                "Failed to create file {}: path already exists",
                safe_file_path.display()
            );
        }

        false
    }

    /// Carve data and write it to a new file.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_255_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// const CARVE_SIZE: usize = 6;
    ///
    /// let data: &[u8] = b"foobarJUNK";
    ///
    /// let file_name = "carved_file.txt";
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.carve_file(file_name, data, 0, CARVE_SIZE), true);
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join(file_name))?, std::str::from_utf8(&data[0..CARVE_SIZE])?);
    /// # Ok(())
    /// } _doctest_main_src_extractors_common_rs_255_0(); }
    /// ```
    pub fn carve_file(
        &self,
        file_path: impl AsRef<Path>,
        data: &[u8],
        start: usize,
        size: usize,
    ) -> bool {
        if let Some(file_data) = data.get(start..start + size) {
            self.create_file(file_path, file_data)
        } else {
            error!(
                "Failed to create file {}: data offset/size are invalid",
                file_path.as_ref().display()
            );
            false
        }
    }

    /// Creates a device file in the chroot directory.
    ///
    /// Note that this does *not* create a real device file, just a regular file containing the device file info.
    fn create_device(
        &self,
        file_path: impl AsRef<Path>,
        device_type: &str,
        major: usize,
        minor: usize,
    ) -> bool {
        let device_file_contents: String = format!("{device_type} {major} {minor}");
        self.create_file(file_path, &device_file_contents.into_bytes())
    }

    /// Creates a character device file in the chroot directory.
    ///
    /// Note that this does *not* create a real character device, just a regular file containing the text `c <major> <minor>`.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_312_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let dev_major: usize = 1;
    /// let dev_minor: usize = 2;
    /// let file_name = "char_device";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_character_device(file_name, dev_major, dev_minor), true);
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join(file_name))?, "c 1 2");
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_312_0(); }
    /// ```
    pub fn create_character_device(
        &self,
        file_path: impl AsRef<Path>,
        major: usize,
        minor: usize,
    ) -> bool {
        self.create_device(file_path, "c", major, minor)
    }

    /// Creates a block device file in the chroot directory.
    ///
    /// Note that this does *not* create a real block device, just a regular file containing the text `b <major> <minor>`.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_345_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let dev_major: usize = 1;
    /// let dev_minor: usize = 2;
    /// let file_name = "block_device";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_block_device(file_name, dev_major, dev_minor), true);
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join(file_name))?, "b 1 2");
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_345_0(); }
    /// ```
    pub fn create_block_device(
        &self,
        file_path: impl AsRef<Path>,
        major: usize,
        minor: usize,
    ) -> bool {
        self.create_device(file_path, "b", major, minor)
    }

    /// Creates a fifo file in the chroot directory.
    ///
    /// Note that this does *not* create a real fifo, just a regular file containing the text `fifo`.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_377_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let file_name = "fifo_file";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_fifo(file_name), true);
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join(file_name))?, "fifo");
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_377_0(); }
    /// ```
    pub fn create_fifo(&self, file_path: impl AsRef<Path>) -> bool {
        self.create_file(file_path, b"fifo")
    }

    /// Creates a socket file in the chroot directory.
    ///
    /// Note that this does *not* create a real socket, just a regular file containing the text `socket`.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_401_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let file_name = "socket_file";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_socket(file_name), true);
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join(file_name))?, "socket");
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_401_0(); }
    /// ```
    pub fn create_socket(&self, file_path: impl AsRef<Path>) -> bool {
        self.create_file(file_path, b"socket")
    }

    /// Append the provided data to the specified file in the chroot directory.
    ///
    /// If the specified file does not exist, it will be created.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_426_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let file_data: &[u8] = b"foobar";
    /// let file_name = "append.txt";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.append_to_file(file_name, file_data), true);
    /// assert_eq!(std::fs::read_to_string(chroot_dir.join(file_name))?, std::str::from_utf8(file_data)?);
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_426_0(); }
    /// ```
    pub fn append_to_file(&self, file_path: impl AsRef<Path>, data: &[u8]) -> bool {
        let safe_file_path: PathBuf = match self.resolve_in_chroot(&file_path, true) {
            Some(path) => path,
            None => {
                error!(
                    "Refusing to append to {}: path escapes the chroot via a symlink",
                    file_path.as_ref().display()
                );
                return false;
            }
        };

        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(safe_file_path.clone())
        {
            Err(e) => {
                error!(
                    "Failed to open file '{}' for appending: {e}",
                    safe_file_path.display()
                );
            }
            Ok(mut fp) => match fp.write(data) {
                Err(e) => {
                    error!(
                        "Failed to append to file '{}': {e}",
                        safe_file_path.display()
                    );
                }
                Ok(_) => {
                    return true;
                }
            },
        }

        false
    }

    /// Creates a directory in the chroot directory.
    ///
    /// Equivalent to mkdir -p.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let dir_name = "my_directory";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_directory(dir_name), true);
    /// assert_eq!(std::path::Path::new(&chroot_dir).join(dir_name).exists(), true);
    /// ```
    pub fn create_directory(&self, dir_path: impl AsRef<Path>) -> bool {
        let safe_dir_path: PathBuf = match self.resolve_in_chroot(&dir_path, true) {
            Some(path) => path,
            None => {
                error!(
                    "Refusing to create directory {}: path escapes the chroot via a symlink",
                    dir_path.as_ref().display()
                );
                return false;
            }
        };

        match fs::create_dir_all(safe_dir_path.clone()) {
            Ok(_) => {
                return true;
            }
            Err(e) => {
                error!(
                    "Failed to create output directory {}: {e}",
                    safe_dir_path.display()
                );
            }
        }

        false
    }

    /// Delete a directory in the chroot directory.
    ///
    /// Equivalent to rm -rf.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let dir_name = "my_directory";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// assert_eq!(chroot.create_directory(dir_name), true);
    /// assert_eq!(chroot.remove_directory(dir_name), true);
    /// assert_eq!(chroot.remove_directory("i_dont_exist"), true);
    /// ```
    pub fn remove_directory(&self, dir_path: impl AsRef<Path>) -> bool {
        let safe_dir_path: PathBuf = self.chrooted_path(dir_path);

        match fs::exists(safe_dir_path.clone()) {
            Ok(dir_exists) => {
                if !dir_exists {
                    return true;
                }
            }
            Err(e) => {
                error!(
                    "Failed to check if directory {} exists: {e:?}",
                    safe_dir_path.display()
                );
                return false;
            }
        }

        match fs::remove_dir_all(safe_dir_path.clone()) {
            Ok(_) => return true,
            Err(e) => error!(
                "Failed to delete directory {}: {e}",
                safe_dir_path.display()
            ),
        }

        false
    }

    /// Set executable permissions on an existing file in the chroot directory.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let file_name = "runme.exe";
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    /// chroot.create_file(file_name, b"AAAA");
    ///
    /// assert_eq!(chroot.make_executable(file_name), true);
    /// ```
    #[allow(dead_code)]
    pub fn make_executable(&self, file_path: impl AsRef<Path>) -> bool {
        // Make the file globally executable
        const UNIX_EXEC_FLAG: u32 = 1;

        let safe_file_path: PathBuf = self.chrooted_path(file_path);

        match fs::metadata(safe_file_path.clone()) {
            Err(e) => {
                error!(
                    "Failed to get permissions for file {}: {e}",
                    safe_file_path.display()
                );
            }
            Ok(_metadata) => {
                #[cfg(unix)]
                {
                    let mut permissions = _metadata.permissions();
                    let mode = permissions.mode() | UNIX_EXEC_FLAG;
                    permissions.set_mode(mode);

                    match fs::set_permissions(&safe_file_path, permissions) {
                        Err(e) => {
                            error!(
                                "Failed to set permissions for file {}: {e}",
                                safe_file_path.display()
                            );
                        }
                        Ok(_) => {
                            return true;
                        }
                    }
                }
                #[cfg(windows)]
                {
                    return true;
                }
            }
        }

        false
    }

    /// Applies a Unix file mode to an existing path in the chroot directory, preserving
    /// the permission, setuid/setgid, and sticky bits exactly as recorded in the archive.
    ///
    /// On non-Unix platforms this is a no-op that returns `true`.
    pub fn set_mode(&self, file_path: impl AsRef<Path>, mode: u32) -> bool {
        // set_permissions follows symlinks, so resolve the full path through the chroot
        // (refusing anything that escapes) before applying the mode.
        let safe_file_path: PathBuf = match self.resolve_in_chroot(&file_path, true) {
            Some(path) => path,
            None => {
                warn!(
                    "Refusing to set mode on {}: path escapes the chroot via a symlink",
                    file_path.as_ref().display()
                );
                return false;
            }
        };

        #[cfg(unix)]
        {
            if let Err(e) = fs::set_permissions(&safe_file_path, fs::Permissions::from_mode(mode)) {
                warn!("Failed to set mode on {}: {e}", safe_file_path.display());
                return false;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }

        true
    }

    /// Best-effort restore of ownership (uid/gid) on an existing path in the chroot
    /// directory. Uses `lchown`, so it never follows the final symlink component and is
    /// safe to call on symlink entries.
    ///
    /// Changing ownership typically requires privileges (root); failures are ignored, as
    /// an unprivileged `tar`/`cpio` extraction would simply keep the caller's ownership.
    /// On non-Unix platforms this is a no-op that returns `true`.
    pub fn set_ownership(&self, file_path: impl AsRef<Path>, uid: u32, gid: u32) -> bool {
        // lchown leaves the final symlink alone, so resolve the parent directories
        // physically but keep the leaf literal (follow_final = false). A path whose
        // parent escapes the chroot via a symlink is refused.
        let safe_file_path: PathBuf = match self.resolve_in_chroot(&file_path, false) {
            Some(path) => path,
            None => {
                warn!(
                    "Refusing to set ownership on {}: path escapes the chroot via a symlink",
                    file_path.as_ref().display()
                );
                return false;
            }
        };

        #[cfg(unix)]
        {
            if let Err(e) = unix_fs::lchown(&safe_file_path, Some(uid), Some(gid)) {
                // Expected without privileges; don't treat as an extraction failure.
                debug!(
                    "Could not set ownership on {} to {uid}:{gid}: {e}",
                    safe_file_path.display()
                );
                return false;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (uid, gid);
        }

        true
    }

    /// Removes the chroot prefix → returns path relative to chroot root
    /// e.g. "/chroot/bin/ls" → "/bin/ls"
    fn strip_chroot_prefix(&self, path: &Path) -> PathBuf {
        let chroot = Path::new(&self.chroot_directory);

        if self.chroot_directory.is_absolute() && self.chroot_directory.parent().is_none() {
            path.to_path_buf()
        } else if let Ok(stripped) = path.strip_prefix(chroot) {
            if stripped.as_os_str().is_empty() {
                PathBuf::from("/")
            } else {
                PathBuf::from("/").join(stripped)
            }
        } else {
            // fallback / safety
            path.to_path_buf()
        }
    }

    /// Creates a symbolic link in the chroot directory, named `symlink_path`, which points to `target_path`.
    ///
    /// The link target is rewritten to a path relative to the symlink that always
    /// resolves *within* the chroot directory, so neither the symlink nor anything that
    /// follows it can escape the chroot — even when `target_path` is absolute.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_extractors_common_rs_571_0() -> Result<(), Box<dyn std::error::Error>> {
    /// use binwalk_ng::extractors::Chroot;
    ///
    /// let chroot_dir = std::path::Path::new("tests").join("binwalk_unit_tests");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let chroot_dir = temp_dir.path();
    ///
    /// let chroot = Chroot::new(&chroot_dir);
    ///
    /// // Create the target file, then a symlink that points at it.
    /// chroot.create_file("target", b"data");
    /// assert_eq!(chroot.create_symlink("symlink", "target"), true);
    ///
    /// // The link is relative and chroot-contained, so reading through it yields the target.
    /// assert_eq!(std::fs::read_to_string(std::path::Path::new(&chroot_dir).join("symlink"))?, "data");
    /// # Ok(())
    /// # } _doctest_main_src_extractors_common_rs_571_0(); }
    /// ```
    pub fn create_symlink(
        &self,
        symlink_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
    ) -> bool {
        let symlink = symlink_path.as_ref();
        let target = target_path.as_ref();

        // Resolve where the symlink will be placed, following its parent directories
        // physically but keeping the leaf literal (the link itself must not be followed).
        // Refuse if its parent escapes the chroot via a symlink.
        let safe_symlink = match self.resolve_in_chroot(symlink, false) {
            Some(path) => path,
            None => {
                error!(
                    "Refusing to create symlink {}: path escapes the chroot via a symlink",
                    symlink.display()
                );
                return false;
            }
        };

        let safe_target_base = if target.is_absolute() {
            self.chrooted_path(target)
        } else {
            // Relative target → resolve relative to symlink's parent
            let parent = safe_symlink.parent().unwrap_or_else(|| Path::new("/"));
            self.safe_path_join(parent, target)
        };

        let symlink_inside = self.strip_chroot_prefix(&safe_symlink);
        let target_inside = self.strip_chroot_prefix(&safe_target_base);

        // Build a relative path from the symlink's location to the target so the link
        // always resolves *within* the chroot directory and can never point outside it
        // (even when the archive's target is absolute, e.g. "/etc/passwd").
        let mut relative_target = PathBuf::new();

        // Number of ".." needed to climb from the symlink's directory back to the
        // chroot root: total components, minus the leading root, minus the symlink
        // file itself.
        let depth = symlink_inside.components().count().saturating_sub(2);
        for _ in 0..depth {
            relative_target.push("..");
        }

        // Append the target as a path relative to the chroot root (strip its leading
        // '/'), so the final link never starts with '/' and stays chroot-contained.
        relative_target.push(target_inside.strip_prefix("/").unwrap_or(&target_inside));

        // Create the symlink

        #[cfg(unix)]
        {
            match unix_fs::symlink(&relative_target, &safe_symlink) {
                Ok(()) => true,
                Err(e) => {
                    error!("Failed to create symlink {symlink:?} -> {target:?} : {e}");
                    false
                }
            }
        }

        #[cfg(windows)]
        {
            // Windows needs to know whether it's a file or directory symlink
            // But most chroot-like environments are Unix-like, so often people
            // just use symlink_file() or always use symlink_dir() — choose wisely

            // try file symlink first
            if let Ok(()) = std::os::windows::fs::symlink_file(&relative_target, &safe_symlink) {
                return true;
            }

            // try directory symlink if file failed
            match std::os::windows::fs::symlink_dir(&relative_target, &safe_symlink) {
                Ok(()) => true,
                Err(e) => {
                    error!("Failed to create symlink {symlink:?} -> {target:?} : {e}");
                    false
                }
            }
        }
    }

    /// Resolves `raw_path` (an extraction-relative or archive-absolute path) against the
    /// chroot directory, following every symlink component, and returns the real on-disk
    /// path it maps to — but only if that path stays *inside* the chroot.
    ///
    /// Resolution is *physical*, like `realpath`: a `..` after a symlink pops the symlink's
    /// resolved target, not the literal link name. The two kinds of `..` are treated
    /// differently, however:
    ///
    /// * `..` (and absolute roots) coming from the **input path** are *clamped* at the
    ///   chroot root — creating `../x` simply lands inside the chroot, as a well-behaved
    ///   `tar`/`cpio` extractor would do. The caller's own path can never make this escape.
    /// * `..` (or an absolute target) coming from a **symlink already on disk** is allowed
    ///   to climb, but if it resolves *outside* the chroot the whole path is rejected
    ///   (`None`). We never follow a real symlink out of the sandbox, even though nothing
    ///   created through the `Chroot` API could produce such an escaping link.
    ///
    /// Also returns `None` on a symlink loop (more than `MAX_SYMLINK_DEPTH` hops).
    ///
    /// When `follow_final` is false the final component is placed literally and is *not*
    /// followed (used when the leaf is the entry being created, e.g. a symlink, or when
    /// the operation must act on the link itself such as `lchown`); its parent directories
    /// are still resolved physically.
    fn resolve_in_chroot(&self, raw_path: impl AsRef<Path>, follow_final: bool) -> Option<PathBuf> {
        // Maximum number of symlinks to follow before giving up (matches Linux MAXSYMLINKS),
        // guarding against symlink loops.
        const MAX_SYMLINK_DEPTH: usize = 40;

        // Owned representation of a single path component, so symlink targets (whose data
        // is owned locally) can be pushed onto the work queue without borrow issues.
        enum Seg {
            Root,
            Parent,
            Normal(std::ffi::OsString),
        }

        // Convert a path into owned segments, dropping no-op `.` components.
        fn segments(path: &Path) -> Vec<Seg> {
            path.components()
                .filter_map(|component| match component {
                    Component::RootDir | Component::Prefix(_) => Some(Seg::Root),
                    Component::ParentDir => Some(Seg::Parent),
                    Component::Normal(name) => Some(Seg::Normal(name.to_os_string())),
                    Component::CurDir => None,
                })
                .collect()
        }

        let root = &self.chroot_directory;

        // The default / passthrough chroot (the bare filesystem root, e.g. "/") imposes no
        // containment boundary: input paths are real absolute host paths — including Windows
        // drive prefixes such as `C:\` — that must be preserved verbatim, and nothing can
        // escape the filesystem root anyway. Fall back to the lexical join, which keeps the
        // historical behavior (and avoids corrupting drive-prefixed paths on Windows).
        if root.parent().is_none() {
            return Some(self.chrooted_path(raw_path));
        }

        // `out` is the current, physically resolved location. Each pending segment is
        // tagged with whether it originated from a symlink target (`true`) or the input
        // path (`false`), which governs whether `..` clamps or is allowed to escape.
        let mut out: PathBuf = root.clone();
        let mut pending: VecDeque<(Seg, bool)> = segments(raw_path.as_ref())
            .into_iter()
            .map(|segment| (segment, false))
            .collect();
        let mut symlinks_followed: usize = 0;

        while let Some((segment, from_symlink)) = pending.pop_front() {
            match segment {
                // An absolute input path is interpreted relative to the chroot root. (An
                // absolute symlink target is rejected before it is ever queued, below.)
                Seg::Root => {
                    out = root.clone();
                }
                Seg::Parent => {
                    if from_symlink {
                        // A symlink target climbing upward: allow it for now; the
                        // containment check below rejects the path if it leaves the chroot.
                        out.pop();
                    } else if &out != root {
                        // Input "..": clamp at the chroot root, never climb out.
                        out.pop();
                    }
                }
                Seg::Normal(name) => {
                    let candidate = out.join(&name);

                    // When not following the final component, place it literally and stop.
                    if !follow_final && pending.is_empty() {
                        out = candidate;
                        break;
                    }

                    match fs::symlink_metadata(&candidate) {
                        // Does not exist yet: treat as a plain name. Nothing past a
                        // non-existent name can be a symlink we'd traverse, and a later
                        // `..` simply pops it back.
                        Err(_) => {
                            out = candidate;
                        }
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            symlinks_followed += 1;
                            if symlinks_followed > MAX_SYMLINK_DEPTH {
                                return None;
                            }

                            let target = fs::read_link(&candidate).ok()?;

                            // An absolute symlink target escapes the chroot model.
                            if target.is_absolute() {
                                return None;
                            }

                            // Resolve the (relative) target from the directory containing
                            // the link by push-fronting its components (tagged as
                            // symlink-derived) ahead of the rest.
                            for target_segment in segments(&target).into_iter().rev() {
                                pending.push_front((target_segment, true));
                            }
                        }
                        Ok(_) => {
                            out = candidate;
                        }
                    }
                }
            }

            // A real symlink (or a `..` within its target) must never resolve outside the
            // chroot. Input `..` is clamped above, so this only ever rejects on-disk links.
            if !out.starts_with(root) {
                return None;
            }
        }

        Some(out)
    }

    /// Interprets a given path containing '..' directories.
    fn sanitize_path(&self, file_path: impl AsRef<Path>) -> PathBuf {
        let mut components_stack: Vec<PathBuf> = vec![PathBuf::from("/")];

        for component in file_path.as_ref().components() {
            match component {
                Component::RootDir | Component::CurDir => {
                    // Skip
                }

                Component::ParentDir => {
                    // Prevent traversal above root
                    if components_stack.len() > 1 {
                        components_stack.pop();
                    }
                }

                Component::Normal(part) => {
                    components_stack.push(PathBuf::from(part));
                }

                // Windows prefixes: C:, UNC paths, etc.
                Component::Prefix(prefix) => {
                    components_stack.push(PathBuf::from(prefix.as_os_str()));
                }
            }
        }

        components_stack.iter().collect()
    }
}

impl Default for Chroot {
    fn default() -> Self {
        Self {
            chroot_directory: PathBuf::from("/"),
        }
    }
}

/// Recursively walks a given directory and returns a list of regular non-zero size files in the given directory path.
#[allow(dead_code)]
pub fn get_extracted_files(directory: impl AsRef<Path>) -> Vec<PathBuf> {
    let mut regular_files: Vec<PathBuf> = vec![];

    for entry in WalkDir::new(directory).into_iter() {
        match entry {
            Err(_e) => continue,
            Ok(entry) => {
                let entry_path = entry.path();
                // Query file metadata *without* following symlinks
                match fs::symlink_metadata(entry_path) {
                    Err(_e) => continue,
                    Ok(md) => {
                        // Only interested in non-empty, regular files
                        if md.is_file() && md.len() > 0 {
                            regular_files.push(entry_path.to_path_buf());
                        }
                    }
                }
            }
        }
    }

    regular_files
}

/// Executes an extractor for the provided SignatureResult.
pub fn execute(
    file_data: &[u8],
    file_path: impl AsRef<Path>,
    signature: &SignatureResult,
    extractor: &Option<Extractor>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    // Create an output directory for the extraction
    if let Ok(output_directory) = create_output_directory(&file_path, signature.offset) {
        // Make sure a default extractor was actually defined (this function should not be called if signature.extractor is None)
        match &extractor {
            None => {
                error!(
                    "Attempted to extract {} data, but no extractor is defined!",
                    signature.name
                );
            }

            Some(default_extractor) => {
                // If the signature result specified a preferred extractor, use that instead of the default signature extractor
                let extractor_definition = signature.preferred_extractor.as_ref().map_or_else(
                    || default_extractor.clone(),
                    |preferred_extractor| preferred_extractor.clone(),
                );

                // Decide how to execute the extractor depending on the extractor type
                match &extractor_definition.utility {
                    ExtractorType::None => {
                        error!(
                            "Signature {}: an extractor of type None is invalid!",
                            signature.name
                        );
                    }

                    ExtractorType::Internal(func) => {
                        debug!("Executing internal {} extractor", signature.name);
                        // Run the internal extractor function
                        result = func(file_data, signature.offset, Some(&output_directory));
                        // Set the extractor name to "<signature name>_built_in"
                        result.extractor = format!("{}_built_in", signature.name);
                    }

                    ExtractorType::External(cmd) => {
                        // Spawn the external extractor command
                        match spawn(
                            file_data,
                            file_path,
                            &output_directory,
                            signature,
                            extractor_definition.clone(),
                        ) {
                            Err(e) => {
                                error!(
                                    "Failed to spawn external extractor for '{}' signature: {}",
                                    signature.name, e
                                );
                            }

                            Ok(proc_info) => {
                                // Wait for the external process to exit
                                match proc_wait(proc_info) {
                                    Err(_) => {
                                        warn!("External extractor failed!");
                                    }
                                    Ok(ext_result) => {
                                        result = ext_result;
                                        // Set the extractor name to the name of the extraction utility
                                        result.extractor = cmd.to_string();
                                    }
                                }
                            }
                        }
                    }
                }

                // Populate these ExtractionResult fields automatically for all extractors
                result.output_directory = output_directory.clone();
                result.do_not_recurse = extractor_definition.do_not_recurse;

                // If the extractor reported success, make sure it extracted something other than just an empty file
                if result.success && !was_something_extracted(&result.output_directory) {
                    result.success = false;
                    warn!("Extractor exited successfully, but no data was extracted");
                }
            }
        }

        // Clean up extractor's output directory if extraction failed
        if !result.success
            && let Err(e) = fs::remove_dir_all(&output_directory)
        {
            warn!(
                "Failed to clean up extraction directory {} after extraction failure: {e}",
                output_directory.display()
            );
        }
    }

    result
}

/// Spawn an external extractor process.
fn spawn(
    file_data: &[u8],
    file_path: impl AsRef<Path>,
    output_directory: &Path,
    signature: &SignatureResult,
    mut extractor: Extractor,
) -> Result<ProcInfo, std::io::Error> {
    let chroot = Chroot::default();
    let file_path = file_path.as_ref();

    // This function *only* handles execution of external extraction utilities; internal extractors must be invoked directly
    let command = match &extractor.utility {
        ExtractorType::External(cmd) => cmd.clone(),
        ExtractorType::Internal(_ext) => {
            error!("Tried to run an internal extractor as an external command!");
            return Err(std::io::Error::other(
                "attempt to execute an internal extractor as an external command",
            ));
        }
        ExtractorType::None => {
            error!("An extractor command was defined, but is set to None!");
            return Err(std::io::Error::other(
                "invalid external command of type None",
            ));
        }
    };

    // Carved file path will be <output directory>/<signature.name>_<hex offset>.<extractor.extension>
    let carved_file = format!(
        "{}{}{}_{:X}.{}",
        output_directory.display(),
        path::MAIN_SEPARATOR,
        signature.name,
        signature.offset,
        extractor.extension
    );
    info!(
        "Carving data from {} {:#X}..{:#X} to {}",
        file_path.display(),
        signature.offset,
        signature.offset + signature.size,
        carved_file
    );

    // If the entirety of the source file is this one file type, no need to carve a copy of it, just create a symlink
    if signature.offset == 0 && signature.size == file_data.len() {
        if !chroot.create_symlink(&carved_file, file_path) {
            return Err(std::io::Error::other(
                "Failed to create carved file symlink",
            ));
        }
    } else {
        // Copy file data to carved file path
        if !chroot.carve_file(&carved_file, file_data, signature.offset, signature.size) {
            return Err(std::io::Error::other("Failed to carve data to disk"));
        }
    }

    // Replace all "%e" command arguments with the path to the carved file
    for arg in &mut extractor.arguments {
        if *arg == SOURCE_FILE_PLACEHOLDER {
            *arg = carved_file.clone();
        }
    }

    info!("Spawning process {} {:?}", command, extractor.arguments);
    match process::Command::new(&command)
        .args(&extractor.arguments)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .current_dir(output_directory)
        .spawn()
    {
        Err(e) => {
            error!(
                "Failed to execute command {}{:?}: {}",
                command, extractor.arguments, e
            );
            Err(e)
        }

        Ok(child) => {
            // If the process was spawned successfully, return some information about the process
            let proc_info = ProcInfo {
                child,
                exit_codes: extractor.exit_codes,
                carved_file,
            };
            Ok(proc_info)
        }
    }
}

/// Waits for an extraction process to complete.
/// Returns ExtractionError if the extractor was prematurely terminated, else returns an ExtractionResult.
fn proc_wait(mut worker_info: ProcInfo) -> Result<ExtractionResult, ExtractionError> {
    // The standard exit success value is 0
    const EXIT_SUCCESS: i32 = 0;

    // Block until child process has terminated
    match worker_info.child.wait() {
        // Child was terminated from an external signal, status unknown, assume failure but do nothing else
        Err(e) => {
            error!("Failed to retreive child process status: {e}");
            Err(ExtractionError)
        }

        // Child terminated with an exit status
        Ok(status) => {
            // Assume failure until proven otherwise
            let mut extraction_success = false;

            // Clean up the carved file used as input to the extractor
            debug!("Deleting carved file {}", worker_info.carved_file);
            if let Err(e) = fs::remove_file(worker_info.carved_file.clone()) {
                warn!(
                    "Failed to remove carved file '{}': {}",
                    worker_info.carved_file, e
                );
            };

            // Check the extractor's exit status
            match status.code() {
                None => {
                    extraction_success = false;
                }

                Some(code) => {
                    // Make sure the extractor's exit code is an expected one
                    if code == EXIT_SUCCESS || worker_info.exit_codes.contains(&code) {
                        extraction_success = true;
                    } else {
                        warn!("Child process exited with unexpected code: {code}");
                    }
                }
            }

            // Return an ExtractionResult with the appropriate success status
            Ok(ExtractionResult {
                success: extraction_success,
                ..Default::default()
            })
        }
    }
}

// Create an output directory in which to place extraction results
fn create_output_directory(
    file_path: impl AsRef<Path>,
    offset: usize,
) -> Result<PathBuf, std::io::Error> {
    let chroot = Chroot::default();
    let file_path = file_path.as_ref();

    // Output directory will be: <file_path.extracted/<hex offset>

    let mut dir_name = file_path.file_name().unwrap().to_os_string();
    dir_name.push(".extracted");
    let output_directory = file_path
        .with_file_name(dir_name)
        .join(format!("{:X}", offset));

    // First, remove the output directory if it exists from a previous run
    if !chroot.remove_directory(&output_directory) {
        return Err(std::io::Error::other("Directory deletion failed"));
    }

    // Create the output directory, equivalent of mkdir -p
    if !chroot.create_directory(&output_directory) {
        return Err(std::io::Error::other("Directory creation failed"));
    }

    Ok(output_directory)
}

/// Returns true if the size of the provided extractor output directory is greater than zero.
/// Note that any intermediate/carved files must be deleted *before* calling this function.
fn was_something_extracted(output_directory: impl AsRef<Path>) -> bool {
    let output_directory = output_directory.as_ref();
    debug!(
        "Checking output directory {} for results",
        output_directory.display()
    );

    // Walk the output directory looking for something, anything, that isn't an empty file
    for entry in WalkDir::new(output_directory).into_iter() {
        match entry {
            Err(e) => {
                warn!("Failed to retrieve output directory entry: {e}");
                continue;
            }
            Ok(entry) => {
                // Don't include the base output directory path itself
                if entry.path() == output_directory {
                    continue;
                }

                debug!("Found output file {}", entry.path().display());

                match fs::symlink_metadata(entry.path()) {
                    Err(_e) => continue,
                    Ok(md) => {
                        if md.len() > 0 {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

pub mod dumpifs;
pub mod inflate;
pub mod swapped;
pub mod tsk;

#[cfg(test)]
mod chroot_security_tests {
    use super::Chroot;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink as raw_symlink;
    use std::path::Path;

    /// A symlink that stays *inside* the chroot is followed, not refused: writes through
    /// it are allowed and land at the link's real target. Only links that escape the
    /// chroot are refused (see the tests below).
    #[test]
    fn allows_write_through_inside_pointing_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        assert!(chroot.create_directory("realdir"));
        assert!(chroot.create_symlink("linkdir", "realdir"));

        // create_file / create_directory / append_to_file through the inside-pointing
        // symlink: all allowed.
        assert!(chroot.create_file("linkdir/inside.txt", b"data"));
        assert!(chroot.create_directory("linkdir/sub"));
        assert!(chroot.append_to_file("linkdir/appended.txt", b"more"));

        // Data landed in the real directory the link points at.
        assert_eq!(fs::read(root.join("realdir/inside.txt")).unwrap(), b"data");
        assert!(root.join("realdir/sub").is_dir());
        assert_eq!(
            fs::read(root.join("realdir/appended.txt")).unwrap(),
            b"more"
        );
    }

    /// `..` in the *input path* (not from a symlink) is clamped at the chroot root rather
    /// than refused: creating `../x` just lands inside the chroot, the way a well-behaved
    /// extractor contains a traversal attempt in the archive member name itself.
    #[test]
    fn input_dotdot_is_clamped_not_refused() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        assert!(chroot.create_file("../../../escaped.txt", b"clamped"));
        assert_eq!(fs::read(root.join("escaped.txt")).unwrap(), b"clamped");

        assert!(chroot.create_directory("../../sub/dir"));
        assert!(root.join("sub/dir").is_dir());

        // Nothing landed outside the chroot.
        assert!(!root.parent().unwrap().join("escaped.txt").exists());
    }

    /// A symlink whose target escapes the chroot via `..` must be refused, and nothing
    /// may be written through it. This is the core archive symlink-traversal defense.
    #[cfg(unix)]
    #[test]
    fn refuses_to_write_through_outside_pointing_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        // Plant a raw symlink (bypassing create_symlink's containment) that climbs out
        // of the chroot. The link sits at <chroot>/a/escape so `../../../outside`
        // resolves above the chroot root.
        assert!(chroot.create_directory("a"));
        raw_symlink("../../../outside", root.join("a/escape")).unwrap();

        assert!(!chroot.create_file("a/escape/inside.txt", b"data"));
        assert!(!chroot.create_directory("a/escape/sub"));
        assert!(!chroot.append_to_file("a/escape/inside.txt", b"data"));

        // Nothing was written through the link, inside or outside the chroot.
        assert!(!root.parent().unwrap().join("outside").exists());
    }

    /// A raw symlink with an *absolute* target is treated as an escape and refused, even
    /// though the target path string might happen to exist on the host.
    #[cfg(unix)]
    #[test]
    fn absolute_symlink_target_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        raw_symlink("/etc", root.join("abslink")).unwrap();

        assert!(!chroot.create_file("abslink/passwd", b"data"));
        assert!(!chroot.create_directory("abslink/sub"));
    }

    /// A dangling symlink whose (non-existent) target lies outside the chroot is refused.
    /// This is the canonicalize-`NotFound` case: a missing target must not be mistaken
    /// for a legitimate not-yet-created path.
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_pointing_outside_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        // Target does not exist and resolves above the chroot root.
        raw_symlink("../../../nonexistent_outside", root.join("dangling")).unwrap();

        assert!(!chroot.create_file("dangling/inside.txt", b"data"));
    }

    /// A dangling symlink whose (non-existent) target stays inside the chroot is allowed:
    /// we must not over-refuse paths that simply don't exist yet.
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_pointing_inside_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        // Target does not exist yet but lies inside the chroot.
        raw_symlink("future_dir", root.join("link")).unwrap();

        // The resolver allows it (it does not escape); create_directory (mkdir -p)
        // materializes the path through the dangling link inside the chroot.
        assert!(chroot.create_directory("link/sub"));
        assert!(root.join("future_dir/sub").is_dir());
    }

    /// Chained symlinks that all resolve inside the chroot are followed and allowed.
    #[cfg(unix)]
    #[test]
    fn chained_symlinks_resolving_inside_are_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        assert!(chroot.create_directory("realdir"));
        raw_symlink("b", root.join("a")).unwrap();
        raw_symlink("realdir", root.join("b")).unwrap();

        assert!(chroot.create_file("a/inside.txt", b"chain"));
        assert_eq!(fs::read(root.join("realdir/inside.txt")).unwrap(), b"chain");
    }

    /// A chain of symlinks whose final hop escapes the chroot is refused.
    #[cfg(unix)]
    #[test]
    fn chained_symlink_escaping_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        raw_symlink("b", root.join("a")).unwrap();
        raw_symlink("../../../outside", root.join("b")).unwrap();

        assert!(!chroot.create_file("a/inside.txt", b"data"));
    }

    /// `..` after a symlink resolves against the symlink's *physical* target, not the
    /// literal link name. With `deep -> a/b/c`, `deep/../../x.txt` must land at
    /// `<chroot>/a/x.txt`, not the lexical `<chroot>/x.txt`.
    #[cfg(unix)]
    #[test]
    fn dotdot_through_symlink_resolves_physically() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        assert!(chroot.create_directory("a/b/c"));
        raw_symlink("a/b/c", root.join("deep")).unwrap();

        assert!(chroot.create_file("deep/../../x.txt", b"phys"));
        // Physically resolved: c -> b -> a, then x.txt => <chroot>/a/x.txt.
        assert_eq!(fs::read(root.join("a/x.txt")).unwrap(), b"phys");
        assert!(!root.join("x.txt").exists());
    }

    /// A symlink loop is refused (resolution bails at the depth bound rather than hanging).
    #[cfg(unix)]
    #[test]
    fn symlink_loop_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());
        let root = &chroot.chroot_directory;

        raw_symlink("b", root.join("a")).unwrap();
        raw_symlink("a", root.join("b")).unwrap();

        assert!(!chroot.create_file("a/inside.txt", b"data"));
    }

    /// An absolute archive target (e.g. "/etc/passwd") must become a relative,
    /// chroot-contained link target, never the host's absolute path.
    #[test]
    fn absolute_symlink_target_is_contained() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());

        assert!(chroot.create_symlink("evil", "/etc/passwd"));

        let on_disk_target = fs::read_link(dir.path().join("evil")).unwrap();
        assert!(
            on_disk_target.is_relative(),
            "link target {on_disk_target:?} must be relative, not host-absolute"
        );
        assert_eq!(on_disk_target, Path::new("etc/passwd"));
    }

    /// A relative symlink resolves to its target within the chroot (reading through
    /// the link yields the target's contents).
    #[test]
    fn relative_symlink_resolves_within_chroot() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());

        assert!(chroot.create_file("hello.txt", b"hi"));
        assert!(chroot.create_symlink("link", "hello.txt"));
        assert_eq!(fs::read(dir.path().join("link")).unwrap(), b"hi");
    }

    /// A nested symlink (deeper than the chroot root) also resolves within the chroot.
    #[test]
    fn nested_symlink_resolves_within_chroot() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());

        assert!(chroot.create_directory("a"));
        assert!(chroot.create_file("a/target.txt", b"deep"));
        assert!(chroot.create_symlink("a/link", "target.txt"));
        assert_eq!(fs::read(dir.path().join("a/link")).unwrap(), b"deep");
    }

    /// Ordinary (non-symlink) file and directory creation is unaffected.
    #[test]
    fn ordinary_creation_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(dir.path());

        assert!(chroot.create_directory("x/y"));
        assert!(chroot.create_file("x/y/z.txt", b"ok"));
        assert_eq!(fs::read(dir.path().join("x/y/z.txt")).unwrap(), b"ok");
    }
}
