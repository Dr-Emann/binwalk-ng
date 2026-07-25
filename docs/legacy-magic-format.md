# The binwalk 2.x Magic Signature Format

A reference for the magic signature files shipped with binwalk 2.x
(`src/binwalk/magic/*` on the `minimal_2_patched` branch) and for the pure-Python
libmagic replacement that interprets them (`src/binwalk/core/magic.py`).

Binwalk 2.x does **not** use libmagic. It ships its own parser and matching engine
that reads a *dialect* of the `file(1)` magic format. The dialect is deliberately
similar to libmagic's, so signatures can be lifted from `file`'s `Magdir` with
little editing — but it drops a lot of libmagic and adds a set of binwalk-specific
extensions (curly-brace *tags*) that drive validation, extraction, and scan
control. Anything below that says "binwalk extension" has no libmagic equivalent;
anything that says "differs from libmagic" is a trap for people porting signatures.

---

## Table of contents

1. [Where magic files live and how they are loaded](#1-where-magic-files-live-and-how-they-are-loaded)
2. [Lexical structure of a magic file](#2-lexical-structure-of-a-magic-file)
3. [Anatomy of a signature](#3-anatomy-of-a-signature)
4. [Field 1 — offset](#4-field-1--offset)
5. [Field 2 — data type](#5-field-2--data-type)
6. [Field 3 — comparison value](#6-field-3--comparison-value)
7. [Field 4 — description / format string](#7-field-4--description--format-string)
8. [Tag reference](#8-tag-reference)
9. [The matching engine](#9-the-matching-engine)
10. [Differences from libmagic](#10-differences-from-libmagic)
11. [Common patterns cookbook](#11-common-patterns-cookbook)
12. [Pitfalls and sharp edges](#12-pitfalls-and-sharp-edges)
13. [How signatures feed extraction and plugins](#13-how-signatures-feed-extraction-and-plugins)
14. [Testing a signature](#14-testing-a-signature)

---

## 1. Where magic files live and how they are loaded

### Search paths

Two directories are consulted (`binwalk/core/settings.py`):

| Scope  | Path                                                           |
| ------ | -------------------------------------------------------------- |
| User   | `$XDG_CONFIG_HOME/binwalk/magic/` (falls back to `~/.config/binwalk/magic/`) |
| System | `<python site-packages>/binwalk/magic/`                        |

Every non-hidden file in those directories is a magic file. There is no index and
no `include` directive — the *file names are arbitrary*; they exist only to group
signatures by subject (`filesystems`, `compressed`, `crypto`, `firmware`, …).
Dropping a new file into the user directory is all that is needed to add
signatures. Files starting with `.` are skipped.

`binarch` is special-cased: it is **excluded** from the default load set and is
loaded only when `-A/--opcodes` is given.

`binwalk`, `bincast`, and `code` are deprecated, intentionally comment-only files.
They are shipped solely so that an upgrade overwrites any older installed copy of
the same name.

### Load order and precedence

`binwalk/modules/signature.py` builds the list as *user files first, then system
files*, then feeds each one to `Magic.load()`. Load order matters far less than
you'd expect, though, because after parsing, **all signatures from all files are
sorted globally by confidence** (see §9.3). Load order only breaks ties.

Relevant CLI options:

| Option | Effect |
| ------ | ------ |
| `-B`, `--signature` | Force the default magic file set to be loaded |
| `-m FILE`, `--magic=FILE` | Load a custom magic file *instead of* the defaults (repeatable; combine with `-B` to load both) |
| `-A`, `--opcodes` | Load only `binarch` (user copy, then system copy) |
| `-R BYTES`, `--raw=BYTES` | Synthesize `0 string <BYTES> Raw signature (<BYTES>)` |
| `-I`, `--invalid` | Report results tagged `{invalid}` instead of dropping them |
| `-b`, `--dumb` | Ignore `{jump}` — do not skip ahead after a match |
| `-x STR`, `--exclude=STR` | Drop results whose description matches regex `STR` |
| `-y STR`, `--include=STR` | Keep only results whose description matches regex `STR` |

`-x`/`-y` are applied twice: once at parse time against the *first line's*
description (so filtered signatures are never even compiled), and once at scan
time against the fully rendered description. Matching is case-insensitive
(descriptions are lower-cased first) and uses `re.search`.

### Encoding

Magic files are opened in text mode with the locale default encoding and are
**required to be ASCII**. Scanned file data, by contrast, is decoded `latin-1`, so
one character equals one byte. Any byte ≥ 0x80 you want to match must be written
as an escape (`\xNN` or `\NNN`), never as a literal character — a literal
non-ASCII character will decode to a different code point than the data and never
match.

---

## 2. Lexical structure of a magic file

`Magic.parse()` preprocesses every line as:

```python
line = line.split('#')[0].strip()
if line and line[0] != '!':
    ...
```

Consequences, in order:

1. **`#` always starts a comment — everywhere, including inside a value.**
   There is no escaping. To match a literal `#`, you must write `\x23`. This is
   why `misc` spells the Windows Script Encoding header as
   `\x23\x40\x7e\x5e` rather than `#@~^`.
2. **Blank lines are ignored and are *not* signature separators.** Signature
   boundaries are determined purely by indentation level (§3). The blank lines
   between entries in the shipped files are cosmetic.
3. **Lines beginning with `!` are ignored.** This silently discards libmagic's
   `!:mime`, `!:ext`, `!:strength`, and `!:apple` annotations, so `file`'s magic
   can be pasted in without stripping them.
4. Leading and trailing whitespace is stripped.

The surviving line is then split into fields:

```python
parts = line.replace('\\ ', '\\x20').split(None, 3)
```

* Fields are separated by **runs of any whitespace** (spaces or tabs — the shipped
  files mix both freely; alignment is purely cosmetic).
* A backslash-escaped space (`\ `) is rewritten to `\x20` *before* splitting, so
  `\ ` is how you embed a space in a value. In practice the shipped files just
  write `\x20` directly (`0 string \x3c?xml\x20version`).
* `split(None, 3)` means at most 4 fields: **everything after the third whitespace
  run is the description**, spaces and all.

A line must produce **3 or 4 fields**; anything else raises `ParserException`.

---

## 3. Anatomy of a signature

```
[offset]  [data type]  [comparison value]  [description / format string]
```

Example:

```
0      ubelong    0x27051956     uImage header, header size: 64 bytes,
>4     ubelong    x              header CRC: 0x%X,
>8     ubedate    x              created: %s,
>12    belong     <1             {invalid}
>12    ubelong    x              image size: %d bytes,
```

A **signature** is one line at indentation level 0 plus every following line until
the next level-0 line. The leading `>` characters in field 1 give the level:

| Field 1 | Level |
| ------- | ----- |
| `0`     | 0 |
| `>4`    | 1 |
| `>>20`  | 2 |
| `>>>(19.b-1)` | 3 |

The level count is literally `parts[0].count('>')`, so the `>` characters may be
separated from each other or from the offset (`> > 4` also parses as level 2 —
don't rely on it).

### Level semantics

The engine keeps a `max_line_level` cursor, initially `0`:

* A line is evaluated only if `line.level <= max_line_level`. Lines deeper than
  the cursor are skipped entirely.
* If a line **matches**, `max_line_level = line.level + 1` — its children become
  eligible.
* If a line **fails** at level > 0, `max_line_level = line.level` — its children
  become ineligible, but its *siblings* at the same level are still evaluated.
* If the level-0 line fails, evaluation aborts.

Two important consequences:

* **Siblings are not mutually exclusive.** Every sibling at the same level is
  tested and every one that matches appends to the description. This is what makes
  the big `>28 byte 0 OS: OpenBSD` / `>28 byte 1 OS: NetBSD` … enumerations work,
  and it also means a badly written pair of overlapping sibling conditions will
  emit both strings.
* Level-0 must be a single line; there is no way to have two alternative "magic"
  lines in one signature. Write two signatures instead.

### Rules for the level-0 line

* Its comparison value **must not be the wildcard `x`** (`ParserException` at
  parse time) — the engine needs concrete bytes to build its prefilter regex.
* Its offset **must be a plain integer literal**, not an expression. A complex
  offset parses fine but raises `TypeError` during the scan, because the engine
  computes `result_offset = regex_match_offset - signature.offset`.
* A non-zero level-0 offset is legal and useful: it means "the magic bytes are at
  offset N *inside* the structure", and the reported result offset is shifted back
  by N. `0x410 string \x7f\x13\x00\x00\x00\x00 Minix filesystem…` reports the
  offset of the start of the filesystem, not of the superblock magic.

---

## 4. Field 1 — offset

After stripping the `>` characters, the remainder is the offset. The parser tries
`int(offset, 0)`; if that fails the string is kept and evaluated at scan time.

### 4.1 Literal offsets

`int(x, 0)` semantics — the base is inferred from the prefix:

| Form | Example | Value |
| ---- | ------- | ----- |
| Decimal | `192` | 192 |
| Hex | `0x410`, `0X410` | 1040 |
| Octal | `0o755` | 493 |
| Binary | `0b1010` | 10 |
| Negative | `-4` | -4 |

Note that C-style bare-octal (`0755`) is **not** accepted by `int(_, 0)`; it falls
through to the expression evaluator, which will parse it as a syntax error and
yield `None`. Use `0o755` or plain decimal.

All offsets on continuation lines are **relative to the start of the signature**
(the level-0 line's position), not to the start of the file and not to the
previous line.

### 4.2 Arithmetic expressions

Any offset that isn't a plain integer is evaluated by
`binwalk.core.common.MathExpression`, a small AST-walking evaluator. Supported
operators: `+`, `-`, `*`, `/`, `**`, `^`, and unary `+`/`-`. **Not** supported:
`&`, `|`, `<<`, `>>`, `%`.

```
>>(0x0118-0x0FF60)   ulelong   0x80000007   \b, all regions
```

(Xbox XBE: the certificate pointer is a virtual address with base `0x10000`;
subtracting `0x0FF60` converts VA → file offset.)

Beware: `/` is true division, so it produces a `float`. That will propagate into
slice indices and blow up. Avoid division in offsets.

### 4.3 Indirect offsets — `(offset.type ± n)`

The classic libmagic indirect form. The engine reads a value out of the data at
`signature_start + offset` and substitutes it into the expression:

```
>(0x3c.l)      string   PE\0\0    portable (PE)
>(48.l+58)     string   x         description: "%s"
>(198.L+206)   belong   x         \b, file size: %d bytes
>(7.b+40)      string   x         boot partition: "%s"
>>>(19.b-1)    byte     0x0
```

Indirect type characters:

| Char | Read as |
| ---- | ------- |
| `b`, `B` | 1-byte **signed** |
| `s` | 2-byte **signed**, little endian |
| `S` | 2-byte **signed**, big endian |
| `l` | 4-byte **signed**, little endian |
| `L` | 4-byte **signed**, big endian |

Notes:

* Everything is read **signed**. There is no unsigned indirect read; a length
  field with the high bit set will come back negative.
* There is no 8-byte indirect read.
* The inner offset may itself be an expression — `(4+0.L)` is valid, and the
  `&`-relative rewrite (§4.4) exploits this.
* If the read runs past the end of the current data buffer, the value silently
  becomes `0`.
* Multiple indirect reads in one expression are supported; each distinct
  `offset.type` term is resolved once and textually substituted.

### 4.4 Relative offsets — `&` and `&+`

`&N` means "N bytes past the end of the data consumed by the parent line".
`&+N` is an accepted synonym (binwalk extension; libmagic only has `&`).

```
>>18   lelong   x    keysize: %d bytes,
>>>&0  byte     0    {invalid}
>>>&0  string   >\0  mode: "%s",
```

Mechanically, `&` is textually replaced with `<previous_line_end>+`, so `&0`
becomes e.g. `8+0` and is then handed to the normal expression evaluator. That
also means `&` composes with indirect reads: `(&0.L+4)` is valid and appears in
the shipped `firmware` file.

`previous_line_end` is only updated when the **next** line in the signature is at
a deeper level than the current one, and it is set to
`current_line_offset + current_line_size` — where "size" is the type's fixed width,
or, for strings, `len(matched_string)`. So `&` is only meaningful on a line whose
parent is the immediately preceding line.

---

## 5. Field 2 — data type

The type field is parsed in three stages: **operator split → sign prefix →
endianness prefix**.

### 5.1 Base types

| Type | Width | struct format | Notes |
| ---- | ----- | ------------- | ----- |
| `byte` | 1 | `b` / `B` | |
| `short` | 2 | `h` / `H` | |
| `long` | 4 | `i` / `I` | |
| `quad` | 8 | `q` / `Q` | |
| `date` | 4 | `i` / `I` | Unix epoch seconds; rendered via `strftime("%Y-%m-%d %H:%M:%S")` (UTC) |
| `string` | variable | — | See §6.3 |
| `regex` | ≤128 | — | See §6.4 |

Any other type name is a parse error. In particular there is no `float`,
`double`, `pstring`, `search`, `ldate`, `qdate`, `bestring16`, `guid`, `der`,
`indirect`, `name`/`use`, `default`, or `clear`.

### 5.2 Signedness

A leading `u` makes the type unsigned: `ubyte`, `ushort`, `ulong`, `uquad`,
`ubelong`, `ulequad`, `ubedate`, … Without the `u`, the value is **signed**.

This matters constantly. `>4 belong <1 {invalid}` is the idiomatic "reject zero or
negative sizes" check and only works because `belong` is signed.

### 5.3 Endianness

| Prefix | Endianness |
| ------ | ---------- |
| `be…` | big endian |
| `le…` | little endian |
| *(none)* | **big endian** |

**This differs from libmagic**, where an unprefixed `long`/`short` is *host* byte
order. In binwalk, `long` ≡ `belong`. The shipped signatures essentially always
write the prefix explicitly; you should too.

The prefixes stack with `u`, in the order `u` + endianness + base:
`ubelong`, `uleshort`, `ulequad`, `uledate`, `ubedate`.

### 5.4 In-type operators

A type may carry an arithmetic/bitwise operation applied to the value read from
the data **before** the comparison:

```
>3    byte&0x10        !0x10    {invalid}
>9    beshort&0x0fff   x        \b%03x,
>20   leshort+22       x        footer length: %d
>5    byte&0xE0        !0xA0    {invalid}
```

Recognized operators, in the order the parser looks for them:

`**`  `<<`  `>>`  `&`  `|`  `*`  `+`  `-`  `/`  `~`  `^`

Only the **first** one found is used; there is no chaining. The operand may be a
literal or a full expression (including indirect reads), in which case it is
evaluated the same way offsets are.

Caveats:

* `~` is broken: the implementation is `dvalue = ~opvalue`, which **discards the
  value read from the file**. `byte~0xF0` always yields `-241` regardless of the
  data. Don't use it.
* `/` is true division and yields a float.
* Operators are applied to `string` values too (the type guard is commented out in
  the source), which raises a `ParserException` mid-scan. Never put an operator on
  a `string`/`regex` line.

---

## 6. Field 3 — comparison value

### 6.1 Comparison operators

An optional leading operator character selects the test; with no operator, `=` is
implied.

| Op | Meaning in binwalk | libmagic meaning |
| -- | ------------------ | ---------------- |
| `=` | `data == value` | same |
| `!` | `data != value` | same |
| `>` | `data > value` | same |
| `<` | `data < value` | same |
| `&` | `(data & value) != 0` — **any** bit set | **all** bits set |
| `^` | `(data ^ value) != 0` — differs in ≥1 bit | all bits in value clear |
| `\|` | `(data \| value) != 0` — true unless both are 0 | *(no equivalent)* |
| `~` | `data == ~value` | *(negation of value, not a test)* |
| `x` | always true (wildcard) | same |

The `&` and `^` divergences are the single most common porting bug. A libmagic
line meaning "all of these flag bits are set" becomes "any of these flag bits are
set" in binwalk. Where the shipped signatures need "all bits", they use the
in-type operator instead:

```
>3   byte&0x10   !0x10   {invalid}     # bit 0x10 must be set
```

`|` is essentially useless as written and does not appear in the shipped files.
`^` is functionally identical to `!`.

### 6.2 Wildcard `x`

`x` means "read the value, don't test it" — used to pull a field into the
description. It is illegal on the level-0 line.

For `string` types, a wildcard read grabs up to `MAX_STRING_SIZE` = **128** bytes
and then truncates at the first NUL, CR, or LF — unless the `{strlen}`/`{string}`
pair is in play (§8).

### 6.3 String values

String values are decoded with Python's `unicode_escape` codec, so the usual
escapes work:

| Escape | Meaning |
| ------ | ------- |
| `\xNN` | hex byte |
| `\NNN` | octal byte (e.g. `\044` = `$`, `\377` = 0xFF) |
| `\0`, `\n`, `\r`, `\t`, `\\` | the usual C escapes |
| `\ ` | literal space (rewritten to `\x20` before field splitting) |

Examples from the shipped files:

```
0    string   \x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a   lzop compressed data,
192  string   \044\377\256Qi\232                     Nintendo DS Game ROM Image
0    string   \x3c?xml\x20version                    XML document,
```

**String multiplication (binwalk extension).** A `*` in a string value repeats the
preceding text:

```
0   string   \x00*16   Sixteen NUL bytes
```

`value.split('*')` is applied and each trailing factor multiplies the first part,
*before* escape decoding. Multiple factors chain (`AB*2*3` → `AB` × 6). Note this
makes a literal `*` impossible in a string value; use `\x2a`.

A string comparison reads exactly `len(value)` bytes and compares them literally.
Relational operators on strings do lexicographic comparison — `>\0` is the idiom
for "non-empty":

```
>>>&0   string   >\0   mode: "%s",
```

### 6.4 Regex values

`regex` type values are compiled as **Python** regular expressions (`re`), not
POSIX.

```
0   regex   (S[0-35-9]([0-9A-F]{4})([0-9A-F]{2})+\n)+   Motorola S-Record{many}; …
0   regex   (\:([0-9A-F]{2}){5,}\n)+                    Intel HEX data{many}, …
0   regex   /[a-zA-Z0-9\.\-_]{1,25}/[a-zA-Z0-9\.\-_]…   Unix path:
>4  regex   .{0,4096}\x42\x82.webm                      \b, WebM
```

Regex behaviour is asymmetric depending on where the line sits:

* **On the level-0 line**, the compiled regex *is* the prefilter — the engine runs
  `regex.finditer()` over the whole data block. Result offsets come from
  `match.start()`. Because `finditer` yields non-overlapping matches, a regex that
  can match overlapping occurrences will silently miss some.
* **On a continuation line**, the engine slices 128 bytes starting at the line's
  offset and calls `regex.match()` on it — i.e. the pattern is **anchored** at the
  offset and can never see more than 128 bytes. The shipped
  `>4 regex .{0,4096}\x42\x82.webm` is therefore effectively `.{0,122}…`; the
  4096 is aspirational.

Note also that `{` and `}` inside a regex *value* are safe — tag extraction only
runs on field 4.

### 6.5 Numeric values

Everything that is not `string`, `regex`, or `x` is parsed with `int(value, 0)` —
same base rules as offsets (§4.1). Failure is a parse error.

---

## 7. Field 4 — description / format string

Field 4 is optional. When absent (a 3-field line), the line is a pure predicate:
it gates its children but contributes nothing to the output. This is extremely
common:

```
>18    lelong   !0
>>18   lelong   x    compressed size: %d,
```

### 7.1 Assembly

Each matching line's rendered description is collected, and the final description
is `" ".join(parts)`. That is why almost every description in the shipped files
ends with a comma — the join supplies the space.

### 7.2 printf conversions

The rendered value is substituted into the description with Python's `%`
operator. The engine counts the conversions with the regex `%[^%]` and passes the
**same value** once per conversion:

```
>4     ubelong   x   header CRC: 0x%X,
>32    string    x   image name: "%.32s"
>5     lequad    x   uncompressed size: %lld bytes
>9     beshort&0x0fff  x   \b%03x,
```

* `%d`, `%u`, `%x`, `%X`, `%o`, `%s`, `%c`, width/precision/flags — all standard
  Python `%`-formatting.
* `%lld` is rewritten to `%ld` at parse time (`self.format.replace('%ll','%l')`);
  Python then ignores the `l` length modifier. `%lX`, `%ld`, etc. all work.
* `%.32s` / `%.3s` truncation is the standard way to bound a fixed-size name field.
* **`%%` is broken.** The `%[^%]` counter mis-counts it and formatting raises
  `TypeError: not all arguments converted`. Do not put a literal percent sign in a
  description.
* If a description contains more than one conversion, they all receive the same
  value — you cannot interleave two different fields on one line.

### 7.3 `\b` — suppress the joining space

A literal `\b` in a description deletes **the character immediately before it**
in the joined output — normally the space inserted by the join. This is the
libmagic convention for gluing fragments together:

```
0    string   sqsh       Squashfs filesystem, big endian,
>28  beshort  x          version %d.
>30  beshort  x          \b%d,
```

→ `Squashfs filesystem, big endian, version 4.0,`

The substitution is `re.sub(r'.\\b', '', joined)`, applied once at the end, so it
removes exactly one preceding character per `\b`.

### 7.4 Tags

Anything in `{curly braces}` in field 4 is a **tag**, not output. Tags are parsed
out of the description and removed from the printed text, so they can be placed
anywhere — including in the middle of a sentence:

```
>28  byte  0   OS: {invalid}invalid OS,
```

Tag syntax is `{name}` (value `True`) or `{name:value}`. The value may itself
contain printf conversions, which are formatted with the line's data value:

```
>4   lelong   x   {many}{jump:%d}
>34  string   x   {name:%s}
>26  leshort  x   {strlen:%d}
```

After formatting, the engine tries `int(value, 0)`; if that succeeds the tag holds
an integer, otherwise the string.

Tags are stored into a dict that becomes the keyword arguments of the
`SignatureResult` object, which subclasses `binwalk.core.module.Result`. So a tag
name is simply an attribute name on the result — the recognized ones are listed
below, but an unknown tag is not an error, it just sets an inert attribute.
(`{one-of-many}` and `{jump-to-offset:N}`, which appear in commented-out lines in
`binarch` and `executables`, are binwalk 1.x names that are inert today; their
modern spellings are `{many}` and `{jump:N}`.)

---

## 8. Tag reference

| Tag | Type | Where handled | Meaning |
| --- | ---- | ------------- | ------- |
| `{invalid}` | flag | `magic.py`, `signature.py` | Mark the result invalid. Processing of the signature **aborts immediately** unless `-I` was given. By far the most used tag (700+ occurrences). |
| `{size:%d}` | int | `extractor.py`, `signature.py` | Total size of the identified object. Used as the `dd` length during extraction; a result whose `offset + size` exceeds the file size is marked invalid. |
| `{jump:%d}` | int | `signature.py` | After reporting this result, skip forward `N` bytes from the result offset and resume scanning there. Disabled by `-b/--dumb`. A jump past EOF invalidates the result. |
| `{end}` | flag | `signature.py` | Equivalent to jumping to end-of-file — stop scanning the rest of the file. Used by ISO 9660 so the scanner doesn't also report every file inside the image. |
| `{many}` | flag | `signature.py` | Suppress display of *consecutive repeats* of this same signature. The first hit prints; subsequent hits of the same signature id are hidden until a different signature matches. Used for JFFS2 nodes, S-records, Intel HEX. |
| `{once}` | flag | `magic.py` | Show at most one result per signature *title* per file, no matter how many times it matches. Used by the VxWorks symbol-table signatures. |
| `{name:%s}` | str | `extractor.py` | Output file name to use when carving this result out, instead of the default `<offset>.<ext>`. |
| `{strlen:%d}` | int | `magic.py` | Record an explicit string length for a later line to use. |
| `{string}` | flag | `magic.py` | On a wildcard `string` line, read exactly `{strlen}` bytes (set earlier in this signature) rather than stopping at NUL/CR/LF. |
| `{adjust:%d}` | int | `signature.py` | Add a (usually negative) fixup to the reported offset. `binarch` uses `{adjust:-2}` because the ARM prologue signature matches a halfword two bytes into the instruction. |
| `{overlap}` | flag | `magic.py` | Suppress the "self-overlapping signature" warning at load time (§9.2). Purely cosmetic; no effect on matching. |
| `{confidence:%d}` | int | `magic.py` | *Intended* to override the sort weight used to order signatures. **Broken in this revision** — the value is left as a string and the subsequent sort raises `TypeError`. Not used by any shipped signature. |

The `{strlen}` / `{string}` pair is the idiom for length-prefixed names:

```
# ZIP local file header
>26  leshort  x  {strlen:%d}
>30  string   x  name: {string}%s

# ZIP end-of-central-directory comment
>20  leshort  x  \b, comment:
>20  leshort  x  {strlen:%d}
>22  string   x  {string}"%s"
```

`{strlen}` must be set on an *earlier* line of the same signature; `{string}` must
be on the line that actually reads the string.

---

## 9. The matching engine

### 9.1 Two-phase matching

Binwalk does not walk every signature at every offset. Instead:

**Phase 1 — prefilter.** Each signature is reduced to a single compiled regex
built from its level-0 line only:

* `string` → the literal bytes, `re.escape`'d.
* integer types → the value serialized to bytes in the declared endianness and
  width, `re.escape`'d.
* `regex` → the pattern as written (not escaped).

`re.finditer()` is run over the whole data block for each signature.

**Phase 2 — analysis.** For each regex hit, the full signature (all levels) is
evaluated against the data at `match.start() - signature.offset`.

This is why the level-0 line cannot use a wildcard, cannot use an expression
offset, and why in-type operators and comparison operators on the level-0 line
are *ignored by the prefilter* (they are still applied in phase 2, but the regex
is built from the raw value). A level-0 line like `0 belong&0xFF00 0x1200` will
prefilter on the bytes `00 00 12 00`, which is almost certainly not what you want
— keep masks and inequalities on continuation lines.

### 9.2 Self-overlap warning

At load time, each signature's magic byte string is checked against its own
suffixes. If any rotation matches, binwalk prints:

```
WARNING: Signature '…' is a self-overlapping signature!
```

The reason is phase 1: `finditer` does not report overlapping matches, so a
signature like `ABCDAB` can be swallowed by the byte sequence `ABCDABCDAB`. Add
`{overlap}` when the overlap is intentional (`0 string \x90\x90… Intel x86 nops`,
`0 string owowowow… Wind River management filesystem`).

### 9.3 Ordering and offset deduplication

After all files are parsed, signatures are sorted by **confidence descending**,
where confidence defaults to the byte length of the level-0 magic. Longer magic
wins.

During a scan, the engine keeps a set of already-claimed offsets. If a signature
produces a valid result at offset *N*, no later (lower-confidence) signature may
report at offset *N*. `-I/--invalid` disables this suppression, which is why `-I`
output is much noisier than just "invalid results added".

Results are finally sorted by offset before being returned.

### 9.4 Validation

A result is discarded (unless `-I`) if any of the following hold:

* Any matching line carried `{invalid}`.
* The rendered description is empty.
* The rendered description contains a character outside printable ASCII
  (`[ -~]`) — including tabs and newlines. This is a cheap sanity check that
  catches garbage pulled in by `%s` on binary data.
* `offset + size` exceeds the file size (`{size}`).
* `offset + jump` exceeds the file size (`{jump}`).

Because `{invalid}` aborts the signature immediately, **putting cheap invalidity
checks early in a signature makes scanning meaningfully faster.** The shipped
signatures follow this convention consistently.

### 9.5 Data windowing

Files are scanned in 1 MiB blocks with an 8 KiB "peek" appended
(`DEFAULT_BLOCK_READ_SIZE` / `DEFAULT_BLOCK_PEEK_SIZE` in
`binwalk/core/common.py`; the block size is settable with `--block`, the peek size
only via the `BlockFile(peek=…)` API). A signature that matches near the end of a block can
therefore only reach ~8 KiB past its magic bytes. Reads past the end of the
available buffer do not error — `struct.error` is caught and the value becomes
`0`, and string slices simply come back short. A field far from the magic bytes
will silently read as zero rather than failing loudly.

### 9.6 Scan control

`{jump}` and `{end}` feed back into the scanner loop: after a valid result with a
jump, candidate matches before the jump target in the current block are skipped,
and if the target is past the current block the file is seeked and the block
abandoned. This is what stops binwalk from reporting the interior of a squashfs
image as thousands of separate findings.

---

## 10. Differences from libmagic

### Removed

* No `!:mime`, `!:ext`, `!:strength`, `!:apple` (silently skipped).
* No `search`, `pstring`, `float`, `double`, `bestring16`/`lestring16`, `ldate`,
  `qdate`, `beid3`, `guid`, `der`, `octal`, `msdosdate`, `indirect`, `offset`.
* No named signatures — `name` / `use` do not exist, so signatures cannot be
  factored into reusable subroutines.
* No `default` / `clear` / `switch`-like constructs.
* No `\^` / `~` value-modifier flags on string types (`string/c`, `string/W`,
  etc. — flags after a `/` are not parsed).
* No native/host endianness (`long` means big endian).

### Changed

* `&` in the comparison field means "any bit set", not "all bits set".
* `^` in the comparison field means "differs in ≥1 bit" (i.e. `!=`), not "all
  bits clear".
* Unprefixed integer types are big endian, not host endian.
* Descriptions are joined with a single space and then `\b`-processed globally.
* `#` is a comment delimiter *anywhere* on the line, including inside values.

### Added (binwalk extensions)

* The entire `{tag}` mechanism — `{invalid}`, `{size}`, `{jump}`, `{end}`,
  `{many}`, `{once}`, `{name}`, `{strlen}`/`{string}`, `{adjust}`, `{overlap}`,
  `{confidence}`.
* `regex` data type with Python regex syntax.
* String multiplication: `\x00*16`.
* `&+N` as an explicit synonym for the relative offset `&N`.
* Arithmetic operators `**`, `<<`, `>>`, `~` in the type field (libmagic has
  `&`, `|`, `^`, `+`, `-`, `*`, `/`).
* Signature ordering by magic length and per-offset deduplication, which has no
  libmagic analogue (libmagic identifies one file; binwalk finds many embedded
  objects).

---

## 11. Common patterns cookbook

### 11.1 Reject impossible values early

```
0     string   IMG0    IMG0 (VxWorks) header,
>4    belong   <1      {invalid}
>4    belong   x       size: %d
```

Signed comparison plus `<1` catches both zero and negative (i.e. > 2 GiB
unsigned) lengths in one line.

### 11.2 Enumerations

Siblings at one level, one per enumerant, with a `{invalid}`-tagged entry for the
reserved value:

```
>30   byte   0   image type: {invalid} Image,
>30   byte   1   image type: Standalone Program,
>30   byte   2   image type: OS Kernel Image,
…
```

Bracket the enum with range checks so out-of-range values are rejected rather
than producing a description with a hole in it:

```
>9    byte   <0   {invalid}
>9    byte   >4   {invalid}
>9    byte   0    compression method: stored,
…
```

### 11.3 "Must be one of N" via nested negations

Because siblings are not mutually exclusive, "the field must be one of these
values" is expressed as a *chain of negations*, where reaching the bottom means
none matched:

```
0        uleshort   0x1985     JFFS2 filesystem, little endian
>2       uleshort   !0xE001
>>2      uleshort   !0xE002
>>>2     uleshort   !0x2003
>>>>2    uleshort   !0x2004
>>>>>2   uleshort   !0x2006
>>>>>>2  uleshort   !0xE008
>>>>>>>2 uleshort   !0xE009    {invalid}
```

Each `!` that succeeds descends one level; only if *every* negation succeeds does
the `{invalid}` line get reached.

### 11.4 Bit flags

Use the in-type `&` mask when you need "these exact bits":

```
>3   byte&0x10   !0x10   {invalid}
>5   byte&0xE0   !0xA0   {invalid}
```

Use the comparison `&` when "any of these bits" is what you mean:

```
>8   byte   &0x04   multi-volume,
>8   byte   &0x10   slash-switched,
>8   byte   &0x20   backup,
```

### 11.5 Repeating record formats

Report the first record, hide the rest, and skip over each record's payload:

```
0     uleshort   0x1985   JFFS2 filesystem, little endian
>4    lelong     0        {invalid}
>4    lelong     <0       {invalid}
>4    lelong     x        {many}{jump:%d}
```

`{jump:%d}` takes the node length straight from the header, so the scanner walks
the node chain instead of re-scanning every byte.

### 11.6 Length-prefixed strings

```
>26   leshort   x   {strlen:%d}
>30   string    x   name: {string}%s
```

### 11.7 Pointer-following headers

```
0           string   MZ           Microsoft executable,
>0x3c       lelong   <4           {invalid}
>(0x3c.l)   string   !PE\0\0      {invalid}
>(0x3c.l)   string   PE\0\0       portable (PE)
```

The `e_lfanew` field at `0x3c` is validated first, then dereferenced to test the
PE header it points at.

### 11.8 Trailer / footer signatures

Footers get their own signatures and usually carry `{size}` or nothing at all:

```
0     string      PK\x05\x06   End of Zip archive,
>20   leshort+22  <1           invalid{invalid}
>20   leshort+22  x            footer length: %d
```

Note the `+22` in-type operator adding the fixed header size to the variable
comment length.

### 11.9 Marking an object's extent for extraction

```
0    string    FWS        Uncompressed Adobe Flash SWF file,
>3   byte      0          {invalid}
>3   byte      <0         {invalid}
>3   byte      x          Version %d,
>4   ulelong   0          {invalid}
>4   ulelong   x          File size (header included) %d
>4   ulelong   x          {size:%d}
```

A separate line for `{size:%d}` keeps the tag out of the printed sentence.
(`{size:%d}` on the same line as `File size … %d` would work too — tags are
stripped from the format — but the shipped files favour the split form.)

### 11.10 Offset fixups

```
0   uleshort   0xE92D   ARM instructions, function prologue{adjust:-2}
```

The searched halfword sits two bytes into the 4-byte instruction; `{adjust:-2}`
reports the instruction's real address.

---

## 12. Pitfalls and sharp edges

| Pitfall | Detail |
| ------- | ------ |
| `#` inside a value | Truncates the line. Use `\x23`. |
| `*` inside a string value | Triggers string multiplication. Use `\x2a`. |
| `%%` in a description | Raises `TypeError` during the scan. Avoid literal `%`. |
| Two different fields on one description line | Impossible — all conversions get the same value. Split into two lines. |
| `~` in the type field | Discards the file data entirely. Broken; don't use. |
| `/` in a type or offset | True division → floats. |
| Operator on a `string` line | `ParserException` at scan time. |
| `{confidence:N}` | Breaks the signature sort in this revision. |
| Regex on a continuation line | Anchored, and limited to 128 bytes regardless of the pattern. |
| Regex on the level-0 line | `finditer` skips overlapping matches. |
| Wildcard `string` reads | Capped at 128 bytes and cut at the first NUL/CR/LF unless `{strlen}`+`{string}` are used. |
| Fields far from the magic | Beyond ~8 KiB they silently read as `0` (block peek limit). |
| Expression offset on the level-0 line | Parses, then `TypeError`s during the scan. |
| Wildcard on the level-0 line | `ParserException` at load time. |
| Literal non-ASCII bytes in a magic file | Decoded with the locale codec, never matches. Use `\xNN`. |
| Non-printable characters in the final description | Silently invalidates the result. |
| Bare octal offsets (`0755`) | Not parsed as octal; use `0o755`. |
| Short magic strings | Sort to the bottom by confidence and get shadowed by any longer signature at the same offset. |

---

## 13. How signatures feed extraction and plugins

Signature output is *the* interface to the rest of binwalk.

**Extraction rules** (`src/binwalk/config/extract.conf`) match on the **rendered
description text**, lower-cased, as a regex:

```
<regex against description>:<extension>:<command>:<ok exit codes>:<recurse?>
```

```
^gzip compressed data:gz:gzip -d -f '%e':0,2
^squashfs filesystem:squashfs:unsquashfs -d '%%squashfs-root%%' '%e':0:False
```

So the wording of a description is load-bearing — renaming "Squashfs filesystem"
breaks extraction. `{size}` supplies the carve length (default: to end of file)
and `{name}` supplies the output file name.

**Plugins** (`src/binwalk/plugins/`) hook results and can override validity,
size, and jump using knowledge the magic language can't express — CRC checks,
decompression trial runs, header walking:

| Plugin | Trigger (description prefix) | What it does |
| ------ | ---------------------------- | ------------ |
| `jffs2valid` | `jffs2 filesystem` | Verifies the node header CRC |
| `lzmavalid` | `lzma compressed data` | Trial-decompresses the stream |
| `gzipvalid` / `zlibvalid` | `gzip` / `zlib` | Trial-decompresses |
| `ubivalid` | `ubi erase count header` | Header sanity checks |
| `cpio` | `ascii cpio archive` | Walks the entry chain, sets `jump` and `extract` |
| `tar` | `posix tar archive` | Sets `jump` past each member |
| `ziphelper` | `zip archive data` / `end of zip archive` | Tracks archive extents |

Several of these parse fields back out of the description string
(`cpio.py` scrapes `file name: "…"`, `file size: "…"`), which is another reason
description wording is effectively API.

---

## 14. Testing a signature

Point binwalk at a single magic file and turn on invalid results so you can see
which check is failing:

```sh
binwalk -m ./mysigs -I -v target.bin
```

Or exercise the parser directly, which is much faster for iteration:

```python
import binwalk.core.magic

m = binwalk.core.magic.Magic(invalid=True)
m.parse([
    r'0   string   HDR!            My format,',
    r'>4  lelong   <1              {invalid}',
    r'>4  lelong   x               size: %d bytes{size:%d}',
    r'>8  string   x               name: "%s"',
])

data = open('target.bin', 'rb').read().decode('latin-1')
for r in m.scan(data):
    print(r.offset, r.valid, r.size, r.description)
```

Useful checks while iterating:

* `Magic.match(data)` is `scan(data, dlen=1)` — matches only at offset 0.
* Load-time warnings about self-overlap appear on stderr.
* If a signature never fires, check the prefilter first: `sig.regex.pattern` shows
  exactly which bytes are being searched for.
* If a signature fires but never reports, run with `invalid=True` and look at
  where the description stops — that is the line that tagged `{invalid}`.
