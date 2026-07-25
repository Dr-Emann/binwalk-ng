# Format Recognition: binwalk v2 vs. binwalk-ng (main)

A complete inventory of the file/data formats recognized by legacy **binwalk v2**
(branch `minimal_2_patched`, commit `479172c`) compared against the current
**binwalk-ng** `main` (commit `a5a5435`).

## How the two implementations differ

|                     | binwalk v2 (`minimal_2_patched`)                          | binwalk-ng (`main`)                                            |
| ------------------- | --------------------------------------------------------- | -------------------------------------------------------------- |
| Mechanism           | libmagic-format text rules in `src/binwalk/magic/`         | `signatures::Signature` structs in `src/magic.rs`               |
| Rule storage        | 23 magic files, 4940 lines                                 | 96 format modules under `src/formats/`                          |
| Top-level rules     | 448 (414 in the default scan)                              | 114 signatures                                                  |
| Validation          | declarative rules plus `{invalid}` / `{jump}` markers      | a dedicated Rust parser per format                              |
| Result detail       | description string only                                    | description, computed size, and a confidence level              |
| Extraction          | external tools driven by config                            | in-tree extractors plus external commands                       |

The `binarch` magic file (34 rules) is excluded from v2's default signature scan;
it is loaded only for opcode/architecture scans (`-A`). That leaves **414 rules**
in v2's default scan versus **114** in `main`.

The 448 → 114 reduction overstates the change in coverage. v2 spends many rules
enumerating variants of a single format that `main` collapses into one parsed
signature:

| Format                     | v2 rules | `main` signatures |
| -------------------------- | -------: | ----------------: |
| LZMA property-byte variants |      46 |                 1 |
| Mach-O universal binary (by arch count) | 18 |         0 |
| bzip2 (by block size)      |        9 |                 1 |
| Squashfs (endian/compression) |      7 |                 1 |
| VxWorks symbol table       |        6 |                 1 |

The meaningful comparison is therefore by *format family*, which is what the
rest of this document enumerates.

---

## 1. Formats recognized by `main` but not by v2

These 42 signatures have no counterpart in v2's magic files.

### Filesystems

| Signature        | Description               |
| ---------------- | ------------------------- |
| `apfs`           | APple File System         |
| `btrfs`          | BTRFS file system         |
| `logfs`          | LogFS file system         |
| `ntfs`           | NTFS partition            |
| `fat`            | FAT file system           |
| `android_sparse` | Android sparse image      |

v2 mentions NTFS and FAT only as sub-level annotations of the gzip OS field
(`compressed:124`, `compressed:135`), never as standalone filesystem signatures.

### Compression and archives

| Signature   | Description           | Note                                                     |
| ----------- | --------------------- | -------------------------------------------------------- |
| `zstd`      | ZSTD compressed data  | v2 references zstd only as a Squashfs compression sub-field |
| `lzfse`     | LZFSE compressed data |                                                          |
| `deb`       | Debian package file   | "Debian" appears in v2 only inside author comments        |
| `compressd` | compress'd data       | The rule exists in v2 but is commented out (`compressed:96`) |

### Disk and boot structures

| Signature | Description                     |
| --------- | ------------------------------- |
| `mbr`     | DOS Master Boot Record          |
| `efigpt`  | EFI Global Partition Table      |
| `pchrom`  | Intel serial flash for PCH ROM  |

### Firmware headers

| Signature       | Description                          |
| --------------- | ------------------------------------ |
| `chk`           | CHK firmware header (Netgear)        |
| `jboot_arm`     | JBOOT firmware header                |
| `jboot_stag`    | JBOOT STAG header                    |
| `jboot_sch2`    | JBOOT SCH2 header                    |
| `tplink_rtos`   | TP-Link RTOS firmware                |
| `dms`           | DMS firmware image                   |
| `program_store` | Broadcom ProgramStore firmware image |
| `matter_ota`    | Matter OTA firmware                  |
| `dahua_zip`     | Dahua ZIP archive                    |
| `csman`         | CSman DAT file                       |
| `dkbs`          | DKBS firmware header                 |
| `dlke`          | DLK encrypted firmware               |
| `mh01`          | D-Link MH01 firmware image           |
| `dlink_fw`      | D-Link firmware (model-name based)   |
| `dlink_tlv`     | D-Link TLV firmware                  |
| `encrpted_img`  | D-Link Encrpted Image                |
| `shrs`          | SHRS encrypted firmware              |
| `encfw`         | Known encrypted firmware             |
| `eva`           | Fritz!Box EVA kernel image           |

v2's Broadcom rules (`BCRM` header, 96345 header, "Broadcom firmware header")
are unrelated to `main`'s `program_store`, which keys off a 9-byte NUL run at
offset 67 in the ProgramStore header.

### Cryptographic material and constant tables

| Signature                | Description             | Note                                        |
| ------------------------ | ----------------------- | ------------------------------------------- |
| `md5`                    | MD5 hash constants      | v2 has CRC32 and SHA256 tables only         |
| `aes_forward_table`      | AES Forward Table       | v2 has only S-Box and Inverse S-Box         |
| `aes_reverse_table`      | AES Reverse Table       |                                             |
| `aes_rcon`               | AES RCON                |                                             |
| `aes_acceleration_table` | AES Acceleration Table  |                                             |
| `gpg_signed`             | GPG signed file         | magic `\xA3\x01`; distinct from v2's GPG key trust DB |
| `dpapi`                  | DPAPI blob data         |                                             |

### Media

| Signature | Description              |
| --------- | ------------------------ |
| `riff`    | RIFF image               |
| `svg`     | SVG image                |
| `dxbc`    | DirectX shader bytecode  |

---

## 2. Formats recognized by v2 but no longer by `main`

Six magic files have **no** surviving equivalent in `main`: `console`, `sql`,
`ebml`, `encoding`, `phones`, and `animation` — plus `binarch`, whose entire
scanning mode was removed.

### 2.1 Game consoles and ROMs — entire `console` file dropped

- Nintendo Gameboy Music Module
- Gameboy ROM
- Nintendo Game Boy Advance ROM Image
- Nintendo DS Game ROM Image
- Sega MegaDrive/Genesis raw ROM dump
- Sony Playstation executable
- Microsoft Xbox executable (XBE)
- XIP, Microsoft Xbox data
- XTF, Microsoft Xbox data

### 2.2 Databases — entire `sql` file dropped

- SQLite 2.x database
- SQLite 3.x database
- MySQL table definition file
- MySQL MISAM index file
- MySQL MISAM compressed data file
- MySQL ISAM index file
- MySQL ISAM compressed data file
- iRiver Database file

### 2.3 Container and encoding formats — `ebml`, `encoding`, `phones`, `animation` dropped

- EBML file (Matroska / WebM)
- Base64 standard index table
- Base64 SerComm index table
- Samsung modem TOC index
- MPEG transport stream data
- Uncompressed Adobe Flash SWF file

### 2.4 Executables

- Mach-O universal binary (all 18 arch-count variants)
- Compiled Java class data
- BFLT executable
- Executable script (`#!` shebang)
- Cisco IOS microcode
- Cisco IOS experimental microcode
- Microsoft WinCE installer
- Sony Playstation executable
- EST flat binary
- HP 38 binary / HP 38 ASCII
- HP 39 binary / HP 39 ASCII
- HP 48 binary
- HP 49 binary

### 2.5 Archives

- RPM
- XAR archive
- LHa / LHarc archive data — all variants: `lzs`, `lh `, `lhd`, `lh2`, `lh3`, `lh4`, `lh5`, `lh6`, `lh7`
- InstallShield Cabinet archive data
- Microsoft WinCE install header
- BFF volume header (AIX)
- BFF volume entry / compressed / AIXv3
- BitTorrent file
- BORG Backup Archive
- BSA archive, versions 103 and 104
- HPACK archive data
- JAM archive
- LBR archive data
- PARity archive data
- GNU tar incremental snapshot data

### 2.6 Compression

- StuffIt Archive (data)
- StuffIt Deluxe (data)
- StuffIt Deluxe Segment (data)
- StuffIt Archive
- AFX compressed file data
- lzip compressed data
- lrzip compressed data
- rzip compressed data
- Snappy compression, stream identifier
- JAR compressed with pack200
- KGB archive

### 2.7 Filesystems

- Minix filesystem V1 — little/big endian, 14- and 30-character name variants
- QNX4 Boot Block
- QNX6 Super Block
- VMWare3 disk image
- VMWare3 undoable disk image
- VMware4 disk image
- D-Link ROMFS filesystem (`ROMFS v` at offset 0x10) — `main`'s `romfs` matches only `-rom1fs-`
- Wind River management filesystem
- EFS2 Qualcomm filesystem super block (little and big endian)
- MPFS filesystem (Microchip)
- TROC filesystem
- PFS filesystem
- WDK file system, version 2.0
- BSD 2.x filesystem
- Foscam WebUI filesystem
- Netboot image
- DOS Emulator image

### 2.8 Cryptographic material

- OpenSSH RSA1 private key
- OpenSSH DSA public key
- OpenSSH RSA public key
- OpenSSH ECDSA public key — Curve P-256, P-384, P-521
- PGP armored data
- GPG key trust database
- mcrypt 2.2 encrypted data
- mcrypt 2.5 encrypted data
- DES PC1 table
- DES PC2 table
- DES SP1, big and little endian
- DES SP2, big and little endian
- Nagra PK
- Nagra Constant_KEY
- IDEA key
- PEM certificate request — `main` has only a generic `pem_certificate`
- PEM DSA private key — `main` has only a generic `pem_private_key`
- PEM EC private key — likewise

### 2.9 Media and miscellaneous

- TIFF image data, big-endian and little-endian
- Xilinx Virtex/Spartan FPGA bitstream dummy + sync word
- Xen saved domain file
- HTML document header and footer
- XML document (generic) — `main` retains only `svg`
- Windows Script Encoded Data (`screnc.exe`)
- uuencoded data
- Unix path
- Neighborly text
- ZyXEL voice data

### 2.10 Vendor firmware headers

The largest single bloc of removals. None of the following have an equivalent
in `main`:

**Networking / router vendors**

- WRGG firmware header
- CSYS header, little and big endian
- ZynOS header
- ZBOOT firmware header
- AIH0 firmware header
- NSP firmware header, big and little endian
- NPK firmware header (MikroTik)
- Sercomm firmware signature
- Ubicom firmware header
- Beyonwiz firmware header
- Thompson/Alcatel encoded firmware
- Digi International firmware
- QNAP encrypted firmware footer
- `bix` header
- ZyXEL rom-0 configuration block (3 rules)
- Cisco VxWorks firmware header
- IMG0 (VxWorks) header
- Encrypted Hilink uImage firmware header

**Ubiquiti** (6 rules)

- Ubiquiti firmware header, header size 264 bytes (2 rules)
- Ubiquiti firmware header, third party
- Ubiquiti partition header
- Ubiquiti end header, header size 12 bytes
- Signed Ubiquiti end header, RSA 2048 bit
- Ubiquiti firmware additional data

**LANCOM** (5 rules)

- LANCOM firmware header
- LANCOM OEM file
- LANCOM firmware loader
- LANCOM WWAN firmware
- LANCOM file entry

**Broadcom** (3 rules)

- Broadcom header (`BCRM`)
- Broadcom 96345 firmware header
- Broadcom firmware header

**Mediatek** (6 rules)

- Mediatek bootloader
- Mediatek Serial Flash Image
- Mediatek EMMC Flash Image
- Mediatek NOR Flash Image
- Mediatek Boot Header
- Mediatek File Info

**Qualcomm / Android / mobile**

- Qualcomm device tree container
- Qualcomm splash screen
- Qualcomm SBL1
- Nexus bootloader image
- Nexus IMGDATA
- Motorola bootlogo container
- Motorola RLE bootlogo
- Motorola UTAGS
- ATAGs msm partition table (msmptbl)
- Android Backup
- TWRP Backup

**Other embedded / legacy**

- Xerox DLM firmware — start of header, name, version, end of header (4 rules)
- CSR (XAP2) DFU firmware update header
- CSR Bluecore firmware segment
- BLCR (2 rules)
- Aculab VoIP firmware
- HP LaserJet 1000 series downloadable firmware
- Marvell Libertas firmware
- Paged COBALT boot rom
- COBALT boot rom data (flat boot rom or file system)
- Paged Sun/COBALT boot rom
- Roku aimage SB
- Toshiba SSD Firmware Update
- Toshiba EFI capsule
- Amino MCastFS2 (`.mcfs`)
- Intel HEX data
- Intel x86 or x64 microcode
- Windows CE memory segment header — `main` keeps only the `B000FF` image header

### 2.11 Opcode signatures — entire `binarch` file dropped

v2's `-A` architecture scan matched function prologues and epilogues. `main` has
no equivalent scanning mode. The 34 removed rules covered:

MIPS, MIPSEL, MIPS16e, MIPSEL16e, PowerPC (big and little endian), ARM, ARMEB,
AArch64, Intel x86, SPARC, SuperH (big and little endian), Motorola Coldfire,
Ubicom32, AVR8, and AVR32.

---

## 3. Formats present in both

These 72 signatures have counterparts on both sides.

| `main` signature       | Description                        | v2 magic file |
| ---------------------- | ---------------------------------- | ------------- |
| `gzip`                 | gzip compressed data               | compressed    |
| `bzip2`                | bzip2 compressed data              | compressed    |
| `xz`                   | XZ compressed data                 | compressed    |
| `7zip`                 | 7-zip archive data                 | compressed    |
| `lzma`                 | LZMA compressed data               | lzma          |
| `lzop`                 | LZO compressed data                | compressed    |
| `lz4`                  | LZ4 compressed data                | compressed    |
| `zlib`                 | Zlib compressed file               | compressed    |
| `tarball`              | POSIX tar archive                  | archives      |
| `zip`                  | ZIP archive                        | archives      |
| `rar`                  | RAR archive                        | archives      |
| `arj`                  | ARJ archive data                   | archives      |
| `cpio`                 | CPIO ASCII archive                 | archives      |
| `cab`                  | Microsoft Cabinet archive          | archives      |
| `pjl`                  | HP Printer Job Language data       | archives      |
| `squashfs`             | SquashFS file system               | filesystems   |
| `cramfs`               | CramFS filesystem                  | filesystems   |
| `jffs2`                | JFFS2 filesystem                   | filesystems   |
| `yaffs`                | YAFFSv2 filesystem                 | filesystems   |
| `ubi`                  | UBI image                          | filesystems   |
| `ubifs`                | UBIFS image                        | filesystems   |
| `ext`                  | EXT filesystem                     | filesystems   |
| `romfs`                | RomFS filesystem                   | filesystems   |
| `iso9660`              | ISO9660 primary volume             | filesystems   |
| `qcow`                 | QEMU QCOW Image                    | filesystems   |
| `qnx_ifs`              | QNX IFS image                      | filesystems   |
| `dmg`                  | Apple Disk iMaGe                   | misc          |
| `elf`                  | ELF binary                         | executables   |
| `pe`                   | Windows PE binary                  | executables   |
| `wince`                | Windows CE binary image            | firmware      |
| `uimage`               | uImage firmware image              | firmware      |
| `trx`                  | TRX firmware image                 | firmware      |
| `binhdr`               | BIN firmware header                | firmware      |
| `rtk`                  | RTK firmware header                | firmware      |
| `packimg`              | PackImg firmware header            | firmware      |
| `dlob`                 | DLOB firmware header               | firmware      |
| `tplink`               | TP-Link firmware header            | firmware      |
| `seama`                | SEAMA firmware header              | firmware      |
| `arcadyan`             | Arcadyan obfuscated LZMA           | firmware      |
| `autel`                | Autel obfuscated firmware          | firmware      |
| `copyright`            | Copyright text                     | firmware      |
| `srecord`              | Motorola S-record                  | firmware      |
| `srecord_generic`      | Motorola S-record (generic)        | firmware      |
| `android_bootimg`      | Android boot image                 | firmware      |
| `dtb`                  | Device tree blob (DTB)             | firmware      |
| `cfe`                  | CFE bootloader                     | bootloaders   |
| `uboot`                | U-Boot version string              | bootloaders   |
| `linux_kernel`         | Linux kernel version               | linux         |
| `linux_boot_image`     | Linux kernel boot image            | linux         |
| `linux_arm_zimage`     | Linux ARM boot executable zImage   | linux         |
| `linux_arm64_boot_image` | Linux kernel ARM64 boot image    | linux         |
| `vxworks_symtab`       | VxWorks symbol table               | vxworks       |
| `wind_kernel`          | VxWorks WIND kernel version        | vxworks       |
| `ecos`                 | eCos kernel exception handler      | ecos          |
| `uefi_pi_volume`       | UEFI PI firmware volume            | efi           |
| `uefi_capsule`         | UEFI capsule image                 | efi           |
| `pem_certificate`      | PEM certificate                    | crypto        |
| `pem_private_key`      | PEM private key                    | crypto        |
| `pem_public_key`       | PEM public key                     | crypto        |
| `pkcs_der_hash`        | PKCS DER hash                      | crypto        |
| `openssl`              | OpenSSL encryption                 | crypto        |
| `luks`                 | LUKS header                        | crypto        |
| `rsa`                  | RSA encrypted session key          | crypto        |
| `aes_sbox`             | AES S-Box                          | crypto        |
| `crc32`                | CRC32 polynomial table             | hashing       |
| `sha256`               | SHA256 hash constants              | hashing       |
| `png`                  | PNG image                          | images        |
| `jpeg`                 | JPEG image                         | images        |
| `gif`                  | GIF image                          | images        |
| `bmp`                  | BMP image (Bitmap)                 | images        |
| `pdf`                  | PDF document                       | misc          |
| `pcapng`               | Pcap-NG capture file               | network       |

---

## 4. Summary

| Category                    | Count |
| --------------------------- | ----: |
| Recognized by both          |    72 |
| New in `main`               |    42 |
| Dropped since v2 (families) |  ~130 |
| Dropped opcode signatures   |    34 |

`main` traded breadth for precision. What it kept is largely what has a working
parser or extractor behind it and is common in embedded firmware; what it added
covers modern filesystems, additional vendor firmware variants, and crypto
constant tables. What it dropped falls into two groups: desktop and legacy
formats with little bearing on firmware analysis (game ROMs, HP calculators,
StuffIt, LHa), and the long tail of one-off vendor headers that were
description-only rules in v2 with no parser or extractor behind them.

Gaps that may still be worth closing for firmware work: Mach-O, SQLite, RPM,
TIFF, Minix, VMware disk images, the OpenSSH key formats, and `binarch`-style
opcode scanning.

---

## Reproducing this comparison

```sh
git fetch origin minimal_2_patched
git worktree add /tmp/v2 origin/minimal_2_patched

# v2 top-level magic rules (lines not starting with '>' or '#')
grep -hvE '^\s*(#|>|$)' /tmp/v2/src/binwalk/magic/* | wc -l

# main signature names
grep -oE 'name: "[^"]*"\.to_string\(\)' src/magic.rs \
  | sed 's/name: "//;s/"\.to_string()//' | sort
```
