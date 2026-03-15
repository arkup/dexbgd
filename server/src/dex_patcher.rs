/// DEX patcher for live method replacement via JVMTI RedefineClasses.
///
/// Takes raw DEX bytes, finds a named class+method, overwrites its code_item
/// with a simple return payload (or a nop patch), and recomputes the Adler32
/// checksum and SHA-1 signature required by ART's class loader.
///
/// Constraints (in-place only — sufficient for our tiny payloads):
///   - The replacement bytecode must fit within the existing insns allocation.
///   - insns_size and tries_size are left unchanged so ART's sequential
///     code_item walker keeps the correct byte stride.
///   - registers_size is bumped to 1 if the payload uses v0 and the original was 0.

use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PatchError {
    /// DEX magic bytes are not recognised (not a standard DEX file).
    InvalidMagic,
    /// Data ended unexpectedly at the noted location.
    Truncated(&'static str),
    /// No class_def_item matched `class_sig` in this DEX.
    ClassNotFound,
    /// No encoded_method matched `method_name` in the class.
    MethodNotFound,
    /// The method is abstract/native — it has no code_item.
    NoCodeItem,
    /// Replacement payload won't fit in the existing insns allocation.
    PayloadTooLarge { need: usize, have: usize },
    /// `value` string is not one of the known patch values.
    UnknownValue(String),
    /// `to_bci` does not land on an instruction boundary.
    InvalidTarget { bci: u32 },
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::InvalidMagic =>
                write!(f, "not a valid DEX file (bad magic)"),
            PatchError::Truncated(ctx) =>
                write!(f, "DEX file truncated at {}", ctx),
            PatchError::ClassNotFound =>
                write!(f, "class not found in DEX"),
            PatchError::MethodNotFound =>
                write!(f, "method not found in class"),
            PatchError::NoCodeItem =>
                write!(f, "method is abstract or native (no code_item)"),
            PatchError::PayloadTooLarge { need, have } =>
                write!(f, "payload {} code units > existing {} code units (in-place only)",
                    need, have),
            PatchError::UnknownValue(v) =>
                write!(f, "unknown patch value {:?}  \
                    (use void/true/false/null/0/1)", v),
            PatchError::InvalidTarget { bci } =>
                write!(f, "BCI={} is not a valid instruction start \
                    (inside a multi-code-unit instruction)", bci),
        }
    }
}

// ---------------------------------------------------------------------------
// Patch payloads — Dalvik 16-bit code units (little-endian)
// ---------------------------------------------------------------------------
//
//  0x000e  return-void
//  0x0012  const/4 v0, #int 0
//  0x1012  const/4 v0, #int 1
//  0x000f  return v0          (int/boolean)
//  0x0011  return-object v0   (reference / null)

const PAYLOAD_VOID:  &[u16] = &[0x000e];
const PAYLOAD_FALSE: &[u16] = &[0x0012, 0x000f];   // const/4 v0, 0 ; return v0
const PAYLOAD_TRUE:  &[u16] = &[0x1012, 0x000f];   // const/4 v0, 1 ; return v0
const PAYLOAD_NULL:  &[u16] = &[0x0012, 0x0011];   // const/4 v0, 0 ; return-object v0
const PAYLOAD_ZERO:  &[u16] = &[0x0012, 0x000f];   // same encoding as false
const PAYLOAD_ONE:   &[u16] = &[0x1012, 0x000f];   // same encoding as true

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Patch a method to return a constant value.
///
/// `value` must be one of `"void"`, `"true"`, `"false"`, `"null"`, `"0"`, `"1"`.
/// Returns a new Vec<u8> with updated checksums.
pub fn patch_method_return(
    dex: &[u8],
    class_sig: &str,
    method_name: &str,
    value: &str,
) -> Result<Vec<u8>, PatchError> {
    let payload: &[u16] = match value {
        "void"  => PAYLOAD_VOID,
        "true"  => PAYLOAD_TRUE,
        "false" => PAYLOAD_FALSE,
        "null"  => PAYLOAD_NULL,
        "0"     => PAYLOAD_ZERO,
        "1"     => PAYLOAD_ONE,
        other   => return Err(PatchError::UnknownValue(other.to_string())),
    };

    let mut out = dex.to_vec();
    apply_return_patch(&mut out, class_sig, method_name, payload)?;
    narrow_to_single_class(&mut out, class_sig)?;
    zero_inter_section_padding(&mut out);
    fix_checksums(&mut out);
    Ok(out)
}

/// Patch the instruction at `from_bci` in the named method's code item with a
/// Dalvik `goto` instruction that jumps to `to_bci`.
///
/// `from_bci`, `to_bci`, and `instr_width` are in Dalvik code units (each = 2 bytes).
/// `instr_width` is the width of the original instruction at `from_bci` — the goto must
/// fit within this many code units.  Use the width from the disassembly.
///
/// Encoding:
///   goto    (opcode 0x28) — 1 cu, delta fits in  i8  [-128, 127]
///   goto/16 (opcode 0x29) — 2 cu, delta fits in i16  [-32768, 32767]
///   goto/32 (opcode 0x2A) — 3 cu, any 32-bit delta
///
/// If the chosen goto variant requires more code units than `instr_width`, returns
/// `PatchError::PayloadTooLarge`.
///
/// Returns a new Vec<u8> with updated checksums.
pub fn patch_goto(
    dex: &[u8],
    class_sig: &str,
    method_name: &str,
    from_bci: u32,
    to_bci: u32,
    instr_width: u32,
) -> Result<Vec<u8>, PatchError> {
    let mut out = dex.to_vec();

    if to_bci > from_bci {
        // Forward jump: replace [from_bci..to_bci-1] with zero-initializing instructions.
        // Each instruction that writes a register is replaced with const/4 vN, #0 (type "Zero"
        // in ART verifier — compatible with int AND any reference type).  Non-writing
        // instructions are replaced with NOPs.  Code then falls through to to_bci with no
        // new CFG edges, so ART verification always passes.
        apply_preinit_sled(&mut out, class_sig, method_name, from_bci, to_bci)?;
    } else {
        // Backward jump: insert a goto at from_bci pointing back to to_bci.
        // Backward edges are more likely to verify because the type state at from_bci
        // is a superset of the state expected at to_bci (more registers initialised).
        if instr_width == 0 {
            return Err(PatchError::PayloadTooLarge { need: 1, have: 0 });
        }
        let delta = to_bci as i64 - from_bci as i64;
        let payload: Vec<u16> = if delta >= -128 && delta <= 127 {
            let aa = (delta as i8) as u8 as u16;
            vec![aa << 8 | 0x0028]
        } else if instr_width >= 2 && delta >= -32768 && delta <= 32767 {
            vec![0x0029u16, delta as i16 as u16]
        } else if instr_width >= 3 {
            let d32 = delta as i32;
            vec![0x002Au16, d32 as u16, (d32 >> 16) as u16]
        } else {
            return Err(PatchError::PayloadTooLarge {
                need: if delta >= -32768 && delta <= 32767 { 2 } else { 3 },
                have: instr_width as usize,
            });
        };
        apply_goto_patch(&mut out, class_sig, method_name, from_bci, &payload, instr_width)?;
    }

    narrow_to_single_class(&mut out, class_sig)?;
    zero_inter_section_padding(&mut out);
    fix_checksums(&mut out);
    Ok(out)
}

/// Force a conditional branch at `bci` to always be taken or always not taken
/// by inverting its opcode (XOR 1). Covers opcodes 0x32–0x3d (if-eq..if-lez).
///
/// Opcode inversion pairs (all differ by XOR 1):
///   if-eq↔if-ne, if-lt↔if-ge, if-gt↔if-le
///   if-eqz↔if-nez, if-ltz↔if-gez, if-gtz↔if-lez
///
/// Only the opcode byte changes — size, registers, and target offset are
/// unchanged — so ART's verifier accepts the result with no issues.
pub fn patch_branch_force(
    dex: &[u8],
    class_sig: &str,
    method_name: &str,
    bci: u32,
) -> Result<Vec<u8>, PatchError> {
    let mut out = dex.to_vec();

    let code_off = find_code_item_off(&out, class_sig, method_name)?;
    if code_off + 16 > out.len() {
        return Err(PatchError::Truncated("code_item header"));
    }
    let insns_size = r32(&out, code_off + 12);
    if bci >= insns_size {
        return Err(PatchError::PayloadTooLarge { need: bci as usize + 1, have: insns_size as usize });
    }
    let insns_base = code_off + 16;
    let byte_off = insns_base + bci as usize * 2;
    if byte_off >= out.len() {
        return Err(PatchError::Truncated("insns opcode byte"));
    }

    let op = out[byte_off];
    if op < 0x32 || op > 0x3d {
        return Err(PatchError::UnknownValue(format!("opcode 0x{:02x} is not a conditional branch", op)));
    }
    out[byte_off] = op ^ 1;

    narrow_to_single_class(&mut out, class_sig)?;
    zero_inter_section_padding(&mut out);
    fix_checksums(&mut out);
    Ok(out)
}

/// Width of a Dalvik instruction in code units, derived from the opcode byte only.
/// Handles the special NOP pseudo-instructions (switch/fill-array payloads) via the
/// full 16-bit identifier word.
fn dalvik_instr_width_raw(bc: &[u8], byte_off: usize) -> usize {
    if byte_off >= bc.len() { return 1; }
    let op = bc[byte_off];
    match op {
        // Special NOP pseudo-instructions (payload tables)
        0x00 => {
            let ident = if byte_off + 1 < bc.len() {
                (bc[byte_off] as u16) | ((bc[byte_off + 1] as u16) << 8)
            } else { 0 };
            match ident {
                0x0100 => { // packed-switch payload
                    let size = if byte_off + 3 < bc.len() {
                        (bc[byte_off+2] as u32) | ((bc[byte_off+3] as u32) << 8)
                    } else { 0 };
                    (2 + size * 2).max(1) as usize
                }
                0x0200 => { // sparse-switch payload
                    let size = if byte_off + 3 < bc.len() {
                        (bc[byte_off+2] as u32) | ((bc[byte_off+3] as u32) << 8)
                    } else { 0 };
                    (2 + size * 4).max(1) as usize
                }
                0x0300 => { // fill-array-data payload
                    let elem = if byte_off + 3 < bc.len() {
                        (bc[byte_off+2] as u32) | ((bc[byte_off+3] as u32) << 8)
                    } else { 1 };
                    let count = if byte_off + 7 < bc.len() {
                        (bc[byte_off+4] as u32) | ((bc[byte_off+5] as u32) << 8)
                        | ((bc[byte_off+6] as u32) << 16) | ((bc[byte_off+7] as u32) << 24)
                    } else { 0 };
                    (4 + (elem * count + 1) / 2).max(1) as usize
                }
                _ => 1,
            }
        }
        // 1 code unit
        0x01 | 0x04 | 0x07 | 0x0a..=0x12 | 0x1d | 0x1e | 0x21 | 0x27 | 0x28
        | 0x7b..=0x8f | 0xb0..=0xcf => 1,
        // 2 code units
        0x02 | 0x05 | 0x08 | 0x13 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1c
        | 0x1f | 0x20 | 0x22 | 0x23 | 0x29 | 0x2d..=0x3d | 0x44..=0x6d
        | 0x90..=0xaf | 0xd0..=0xe2 => 2,
        // 3 code units
        0x03 | 0x06 | 0x09 | 0x14 | 0x17 | 0x1b | 0x24..=0x26 | 0x2a..=0x2c
        | 0x6e..=0x72 | 0x74..=0x78 => 3,
        // 5 code units
        0x18 => 5,
        _ => 2,
    }
}

/// For a Dalvik instruction at `byte_off`, return the destination register (if any)
/// and whether it is a wide (long/double) pair.
///
/// Returns None for instructions that do not write to a register (invoke, return,
/// branch, aput/iput/sput, throw, goto, etc.).
fn extract_dest_reg(bc: &[u8], byte_off: usize) -> Option<(u8, bool)> {
    if byte_off >= bc.len() { return None; }
    let op  = bc[byte_off];
    let aa  = bc.get(byte_off + 1).copied().unwrap_or(0);
    let a   = aa & 0x0F;
    match op {
        // move vA, vB  (12x)
        0x01 => Some((a, false)),
        // move/from16 vAA, vBBBB  (22x)
        0x02 => Some((aa, false)),
        // move/16 vAAAA, vBBBB  (32x) — dest in bytes 2-3
        0x03 => Some((bc.get(byte_off+2).copied().unwrap_or(0), false)),
        // move-wide vA, vB
        0x04 => Some((a, true)),
        // move-wide/from16 vAA
        0x05 => Some((aa, true)),
        // move-wide/16 — dest in bytes 2-3
        0x06 => Some((bc.get(byte_off+2).copied().unwrap_or(0), true)),
        // move-object vA
        0x07 => Some((a, false)),
        // move-object/from16 vAA
        0x08 => Some((aa, false)),
        // move-object/16
        0x09 => Some((bc.get(byte_off+2).copied().unwrap_or(0), false)),
        // move-result / move-result-object / move-exception
        0x0a | 0x0c | 0x0d => Some((aa, false)),
        // move-result-wide
        0x0b => Some((aa, true)),
        // return/throw/goto/if/switch/aput/iput/sput/invoke/fill-array-data: no dest register
        0x0e..=0x11 | 0x24..=0x27 | 0x28..=0x3d | 0x4b..=0x51 | 0x59..=0x5f
        | 0x67..=0x6d | 0x6e..=0x72 | 0x74..=0x78 | 0x1d | 0x1e => None,
        // const/4 vA  (11n)
        0x12 => Some((a, false)),
        // const/16, const, const/high16  (21s, 31i, 21h)
        0x13..=0x15 => Some((aa, false)),
        // const-wide/16, const-wide/32, const-wide/high16  (21s, 31i, 21h)
        0x16 | 0x17 | 0x19 => Some((aa, true)),
        // const-wide  (51l)
        0x18 => Some((aa, true)),
        // const-string, const-string/jumbo, const-class
        0x1a | 0x1b | 0x1c => Some((aa, false)),
        // check-cast vAA (modifies type of vAA in-place)
        0x1f => Some((aa, false)),
        // instance-of vA, vB, type  (22c) — dest = vA
        0x20 => Some((a, false)),
        // array-length vA, vB  (12x)
        0x21 => Some((a, false)),
        // new-instance vAA  (21c)
        0x22 => Some((aa, false)),
        // new-array vA, vB, type  (22c)
        0x23 => Some((a, false)),
        // aget vAA  (23x): 0x44=aget, 0x45=aget-wide, 0x46..=0x4a=others
        0x44 | 0x46..=0x4a => Some((aa, false)),
        0x45 => Some((aa, true)),   // aget-wide
        // iget vA  (22c): 0x52=iget, 0x53=iget-wide, 0x54..=0x58
        0x52 | 0x54..=0x58 => Some((a, false)),
        0x53 => Some((a, true)),    // iget-wide
        // sget vAA  (21c): 0x60=sget, 0x61=sget-wide, 0x62..=0x66
        0x60 | 0x62..=0x66 => Some((aa, false)),
        0x61 => Some((aa, true)),   // sget-wide
        // unop 12x: dest = vA
        0x7b..=0x8f => {
            // wide result opcodes: neg-long, not-long, int-to-long, int-to-double,
            // long-to-double, float-to-double, double-to-long
            let wide = matches!(op, 0x7d | 0x7e | 0x81 | 0x83 | 0x86 | 0x89 | 0x8b);
            Some((a, wide))
        }
        // binop 23x: dest = vAA
        0x90..=0xaf => {
            let wide = (0x9b..=0xa5).contains(&op) || (0xab..=0xaf).contains(&op);
            Some((aa, wide))
        }
        // binop/2addr 12x: dest = vA (also source)
        0xb0..=0xcf => {
            let wide = (0xbb..=0xc5).contains(&op) || (0xcb..=0xcf).contains(&op);
            Some((a, wide))
        }
        // binop/lit16 22s: dest = vA
        0xd0..=0xd7 => Some((a, false)),
        // binop/lit8 22b: dest = vAA
        0xd8..=0xe2 => Some((aa, false)),
        _ => None,
    }
}

/// Replace instructions in `[from_bci..to_bci)` with zero-initializing equivalents.
///
/// For each instruction that writes a destination register vD:
///   • Non-wide: `const/4 vD, #0`  (1 CU, vD 0-15) or `const/16 vD, #0`  (2 CU, any)
///   • Wide:     `const-wide/16 vD, #0`  (2 CU)
/// Instructions that do not write a register are replaced with NOP code-units (0x0000).
/// Remaining code units of wider instructions are also zeroed (NOP-padded).
///
/// Because no new CFG edges are introduced (purely sequential fall-through), the ART
/// verifier always accepts the patched method.  The "Zero" type produced by const #0 is
/// compatible with both `int` and any reference type in the ART type system.
fn apply_preinit_sled(
    data: &mut Vec<u8>,
    class_sig: &str,
    method_name: &str,
    from_bci: u32,
    to_bci: u32,
) -> Result<(), PatchError> {
    let code_off = find_code_item_off(data, class_sig, method_name)?;
    if code_off + 16 > data.len() {
        return Err(PatchError::Truncated("code_item header (preinit)"));
    }
    let insns_size = r32(data, code_off + 12) as usize; // in code units
    let insns_base = code_off + 16;

    // Verify to_bci is a valid instruction start by walking the instruction stream.
    {
        let mut bci: usize = 0;
        let mut found = false;
        while bci < insns_size {
            if bci == to_bci as usize { found = true; break; }
            let byte_off = insns_base + bci * 2;
            let w = dalvik_instr_width_raw(data, byte_off);
            bci += if w > 0 { w } else { 1 };
        }
        if !found {
            return Err(PatchError::InvalidTarget { bci: to_bci });
        }
    }

    // Walk [from_bci..to_bci) and replace each instruction.
    let mut bci = from_bci as usize;
    while bci < to_bci as usize && bci < insns_size {
        let byte_off = insns_base + bci * 2;
        if byte_off >= data.len() { break; }

        let w = dalvik_instr_width_raw(data, byte_off);
        let width = if w > 0 { w } else { 1 };
        let byte_width = width * 2;

        let dest = extract_dest_reg(data, byte_off);

        // Zero out all bytes for this slot first.
        for i in 0..byte_width {
            if byte_off + i < data.len() { data[byte_off + i] = 0; }
        }

        match dest {
            Some((reg, false)) if reg <= 15 => {
                // const/4 vA, #0  (opcode 0x12, 1 CU)
                // [0x12 | (0 << 4)] [reg] ... but format is [op][A|B] where B=0
                // Byte encoding: op=0x12, high byte = 0 (literal) | (reg nibble)
                // Format 11n: |A|op| #+B|, A = dest (hi nibble of byte 1), B = value (lo nibble)
                // So: byte[0] = 0x12, byte[1] = (0 << 4) | (reg & 0xF)  ... wait
                // Actually format 11n: AA = dest register, BB = value nibble?
                // No: format 11n is one code unit: [B|A|op] where A=dest(4b), B=value(4b signed)
                // In little-endian 16-bit: low byte = op (0x12), high byte = B<<4|A
                // For const/4 vA, #0: B=0, A=reg → high byte = (0<<4)|reg = reg
                if byte_off + 1 < data.len() {
                    data[byte_off]     = 0x12;
                    data[byte_off + 1] = reg & 0x0F;
                }
            }
            Some((reg, false)) if width >= 2 => {
                // const/16 vAA, #0  (opcode 0x13, 2 CU)
                // Format 21s: [AA|op] [BBBB] where BBBB=0
                if byte_off + 1 < data.len() {
                    data[byte_off]     = 0x13;
                    data[byte_off + 1] = reg;
                    // bytes 2,3 already zero
                }
            }
            Some((reg, true)) if width >= 2 => {
                // const-wide/16 vAA, #0  (opcode 0x16, 2 CU)
                if byte_off + 1 < data.len() {
                    data[byte_off]     = 0x16;
                    data[byte_off + 1] = reg;
                    // bytes 2,3 already zero
                }
            }
            _ => {
                // No register dest or not enough space for an initializer: NOP fill.
                // bytes already zeroed above (0x0000 = NOP)
            }
        }

        bci += width;
    }

    Ok(())
}

/// Nop out `width` code units at `offset` within the named method's insns array.
///
/// `offset` and `width` are in Dalvik code units (each = 2 bytes).
/// Returns a new Vec<u8> with updated checksums.
pub fn patch_method_nop(
    dex: &[u8],
    class_sig: &str,
    method_name: &str,
    offset: u32,
    width: u32,
) -> Result<Vec<u8>, PatchError> {
    let mut out = dex.to_vec();
    apply_nop_patch(&mut out, class_sig, method_name, offset, width)?;
    narrow_to_single_class(&mut out, class_sig)?;
    zero_inter_section_padding(&mut out);
    fix_checksums(&mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Inter-section padding cleanup
// ---------------------------------------------------------------------------

/// Read a signed LEB128 value, advancing `*pos`.
fn sleb128(data: &[u8], pos: &mut usize) -> Option<i32> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() { return None; }
        let byte = data[*pos]; *pos += 1;
        result |= ((byte & 0x7f) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 32 && (byte & 0x40) != 0 { result |= -(1i32 << shift); }
            return Some(result);
        }
        if shift > 35 { return None; }
    }
}

/// Skip one `encoded_value` entry, advancing `pos`.
fn read_encoded_value(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() { return None; }
    let header     = data[*pos]; *pos += 1;
    let value_arg  = (header >> 5) as usize;
    let value_type = header & 0x1f;
    match value_type {
        0x00 => {                                              // VALUE_BYTE: always 1 extra byte
            if *pos >= data.len() { return None; }
            *pos += 1;
        }
        0x02 | 0x03 | 0x04 | 0x06 |                           // SHORT/CHAR/INT/LONG
        0x10 | 0x11 |                                          // FLOAT/DOUBLE
        0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b => {  // METHOD_TYPE..ENUM: value_arg+1 bytes
            let n = value_arg + 1;
            if *pos + n > data.len() { return None; }
            *pos += n;
        }
        0x1c => read_encoded_array(data, pos)?,                // VALUE_ARRAY
        0x1d => read_encoded_annotation(data, pos)?,           // VALUE_ANNOTATION
        0x1e | 0x1f => {}                                      // VALUE_NULL / VALUE_BOOLEAN: no extra bytes
        _ => return None,
    }
    Some(())
}

/// Skip one `encoded_array` (ULEB128 size + N encoded_values), advancing `pos`.
fn read_encoded_array(data: &[u8], pos: &mut usize) -> Option<()> {
    let size = read_uleb128(data, pos)? as usize;
    for _ in 0..size {
        read_encoded_value(data, pos)?;
    }
    Some(())
}

/// Skip one `encoded_annotation` (type_idx + size + elements), advancing `pos`.
fn read_encoded_annotation(data: &[u8], pos: &mut usize) -> Option<()> {
    read_uleb128(data, pos)?;                        // type_idx
    let size = read_uleb128(data, pos)? as usize;
    for _ in 0..size {
        read_uleb128(data, pos)?;                    // name_idx
        read_encoded_value(data, pos)?;
    }
    Some(())
}

/// Skip one `debug_info_item` (line_start, params, then state-machine opcodes until
/// DBG_END_SEQUENCE), advancing `pos`.
fn read_debug_info_item(data: &[u8], pos: &mut usize) -> Option<()> {
    read_uleb128(data, pos)?;                        // line_start
    let params = read_uleb128(data, pos)? as usize;
    for _ in 0..params {
        read_uleb128(data, pos)?;                    // parameter_name (uleb128p1)
    }
    loop {
        if *pos >= data.len() { return None; }
        let opcode = data[*pos]; *pos += 1;
        match opcode {
            0x00 => break,                           // DBG_END_SEQUENCE
            0x01 => { read_uleb128(data, pos)?; }   // DBG_ADVANCE_PC: addr_diff
            0x02 => { sleb128(data, pos)?; }         // DBG_ADVANCE_LINE: line_diff
            0x03 => {                                // DBG_START_LOCAL
                read_uleb128(data, pos)?;            //   register_num
                read_uleb128(data, pos)?;            //   name_idx (uleb128p1)
                read_uleb128(data, pos)?;            //   type_idx (uleb128p1)
            }
            0x04 => {                                // DBG_START_LOCAL_EXTENDED
                read_uleb128(data, pos)?;            //   register_num
                read_uleb128(data, pos)?;            //   name_idx (uleb128p1)
                read_uleb128(data, pos)?;            //   type_idx (uleb128p1)
                read_uleb128(data, pos)?;            //   sig_idx  (uleb128p1)
            }
            0x05 | 0x06 => {                         // DBG_END_LOCAL / DBG_RESTART_LOCAL
                read_uleb128(data, pos)?;            //   register_num
            }
            0x07 | 0x08 => {}                        // DBG_SET_PROLOGUE_END / DBG_SET_EPILOGUE_BEGIN
            0x09 => { read_uleb128(data, pos)?; }   // DBG_SET_FILE: name_idx (uleb128p1)
            _ => {}                                  // 0x0a..0xff: special opcodes, no args
        }
    }
    Some(())
}

/// Compute the byte offset one past the last byte of a map section.
/// Returns None for section types that cannot be walked.
fn map_section_end(data: &[u8], sect_type: u32, offset: usize, count: usize) -> Option<usize> {
    let n = data.len();
    match sect_type {
        // Fixed-size item sections
        0x0000 => Some(offset + 112),
        0x0001 => Some(offset + count * 4),
        0x0002 => Some(offset + count * 4),
        0x0003 => Some(offset + count * 12),
        0x0004 => Some(offset + count * 8),
        0x0005 => Some(offset + count * 8),
        0x0006 => Some(offset + count * 32),
        // map_list: u32 list_size + list_size * map_item(12 bytes)
        0x1000 => {
            if offset + 4 > n { return None; }
            let sz = r32(data, offset) as usize;
            Some(offset + 4 + sz * 12)
        }
        // type_list: `count` items, each = u32 size + size*u16, 4-byte aligned
        0x1001 => {
            let mut pos = offset;
            for _ in 0..count {
                if pos + 4 > n { return None; }
                let sz = r32(data, pos) as usize;
                pos += 4 + sz * 2;
                pos = (pos + 3) & !3;
            }
            Some(pos)
        }
        // annotation_set_ref_list: `count` items, each = u32 size + size*u32
        0x1002 => {
            let mut pos = offset;
            for _ in 0..count {
                if pos + 4 > n { return None; }
                let sz = r32(data, pos) as usize;
                pos += 4 + sz * 4;
            }
            Some(pos)
        }
        // annotation_set_item: `count` items, each = u32 size + size*u32
        0x1003 => {
            let mut pos = offset;
            for _ in 0..count {
                if pos + 4 > n { return None; }
                let sz = r32(data, pos) as usize;
                pos += 4 + sz * 4;
            }
            Some(pos)
        }
        // class_data_item: variable ULEB128 encoding
        0x2000 => {
            let mut pos = offset;
            for _ in 0..count {
                let sf  = read_uleb128(data, &mut pos)? as usize;
                let inf = read_uleb128(data, &mut pos)? as usize;
                let dm  = read_uleb128(data, &mut pos)? as usize;
                let vm  = read_uleb128(data, &mut pos)? as usize;
                for _ in 0..(sf + inf) {
                    read_uleb128(data, &mut pos)?; // field_idx_diff
                    read_uleb128(data, &mut pos)?; // access_flags
                }
                for _ in 0..(dm + vm) {
                    read_uleb128(data, &mut pos)?; // method_idx_diff
                    read_uleb128(data, &mut pos)?; // access_flags
                    read_uleb128(data, &mut pos)?; // code_off
                }
            }
            Some(pos)
        }
        // code_item: 16-byte header + insns + optional tries/handlers; each 4-byte aligned
        0x2001 => {
            let mut pos = offset;
            for _ in 0..count {
                pos = (pos + 3) & !3; // 4-byte align each code_item
                if pos + 16 > n { return None; }
                let tries = r16(data, pos + 6) as usize;
                let insns = r32(data, pos + 12) as usize;
                pos += 16 + insns * 2;
                if tries > 0 {
                    if insns % 2 != 0 { pos += 2; } // 4-byte align for try_items
                    pos += tries * 8;
                    // encoded_catch_handler_list
                    let handlers = read_uleb128(data, &mut pos)? as usize;
                    for _ in 0..handlers {
                        let pair_count = sleb128(data, &mut pos)?;
                        for _ in 0..pair_count.unsigned_abs() as usize {
                            read_uleb128(data, &mut pos)?; // type_idx
                            read_uleb128(data, &mut pos)?; // addr
                        }
                        if pair_count <= 0 { read_uleb128(data, &mut pos)?; } // catch_all_addr
                    }
                }
            }
            Some(pos)
        }
        // string_data_item: ULEB128 utf16_size + null-terminated MUTF-8
        0x2002 => {
            let mut pos = offset;
            for _ in 0..count {
                loop { // skip ULEB128
                    if pos >= n { return None; }
                    let b = data[pos]; pos += 1;
                    if b & 0x80 == 0 { break; }
                }
                while pos < n && data[pos] != 0 { pos += 1; } // find null
                if pos < n { pos += 1; }
            }
            Some(pos)
        }
        // debug_info_item: line_start + params + state-machine until DBG_END_SEQUENCE
        0x2003 => {
            let mut pos = offset;
            for _ in 0..count {
                read_debug_info_item(data, &mut pos)?;
            }
            Some(pos)
        }
        // annotation_item: visibility byte + encoded_annotation
        0x2004 => {
            let mut pos = offset;
            for _ in 0..count {
                if pos >= n { return None; }
                pos += 1;                              // visibility byte
                read_encoded_annotation(data, &mut pos)?;
            }
            Some(pos)
        }
        // encoded_array_item: just an encoded_array (size + values)
        0x2005 => {
            let mut pos = offset;
            for _ in 0..count {
                read_encoded_array(data, &mut pos)?;
            }
            Some(pos)
        }
        // annotations_directory_item
        0x2006 => {
            let mut pos = offset;
            for _ in 0..count {
                if pos + 16 > n { return None; }
                let fs = r32(data, pos +  4) as usize;
                let ms = r32(data, pos +  8) as usize;
                let ps = r32(data, pos + 12) as usize;
                pos += 16 + (fs + ms + ps) * 8;
            }
            Some(pos)
        }
        _ => None,
    }
}

/// Zero all inter-section padding bytes in the DEX.
///
/// ART's `RedefineClasses` verifier requires strict zero-padding between DEX
/// sections.  APKs compiled with older dx/d8 toolchains frequently contain
/// non-zero bytes in these gaps, which causes `JVMTI_ERROR_INVALID_CLASS_FORMAT`
/// (err=60) even when the rest of the DEX is structurally sound.
///
/// Algorithm:
///   1. Read the map_list and sort all section entries by offset.
///   2. For each section whose byte-end we can compute, zero any bytes between
///      that end and the start of the next section.
fn zero_inter_section_padding(data: &mut Vec<u8>) {
    if data.len() < 112 { return; }
    let map_off = r32(data, 52) as usize;
    if map_off + 4 > data.len() { return; }
    let map_count = r32(data, map_off) as usize;
    if map_count > 256 { return; }

    let mut sects: Vec<(u32, usize, usize)> = Vec::with_capacity(map_count);
    for i in 0..map_count {
        let e = map_off + 4 + i * 12;
        if e + 12 > data.len() { break; }
        let t = u16::from_le_bytes(data[e..e+2].try_into().unwrap()) as u32;
        let c = r32(data, e + 4) as usize;
        let o = r32(data, e + 8) as usize;
        sects.push((t, c, o));
    }
    sects.sort_by_key(|s| s.2);

    for i in 0..sects.len() {
        let (t, c, o) = sects[i];
        let next_o = if i + 1 < sects.len() { sects[i+1].2 } else { data.len() };
        if let Some(end) = map_section_end(data, t, o, c) {
            if end < next_o {
                let limit = next_o.min(data.len());
                if end <= limit {
                    for b in &mut data[end..limit] { *b = 0; }
                }
            }
        }
    }
}

/// Dump MAP section layout for diagnostics.  Shows each section, its computed end,
/// how many bytes the gap to the next section is, and whether the gap contains
/// any non-zero bytes.
pub fn dump_section_map(dex: &[u8]) -> String {
    if dex.len() < 112 { return "DEX too short".to_string(); }
    let map_off = r32(dex, 52) as usize;
    if map_off + 4 > dex.len() { return "bad map_off".to_string(); }
    let map_count = r32(dex, map_off) as usize;

    let mut sects: Vec<(u32, usize, usize)> = Vec::new();
    for i in 0..map_count.min(256) {
        let e = map_off + 4 + i * 12;
        if e + 12 > dex.len() { break; }
        let t = u16::from_le_bytes(dex[e..e+2].try_into().unwrap()) as u32;
        let c = r32(dex, e + 4) as usize;
        let o = r32(dex, e + 8) as usize;
        sects.push((t, c, o));
    }
    sects.sort_by_key(|s| s.2);

    let type_name = |t: u32| match t {
        0x0000 => "HEADER", 0x0001 => "STRING_ID", 0x0002 => "TYPE_ID",
        0x0003 => "PROTO_ID", 0x0004 => "FIELD_ID", 0x0005 => "METHOD_ID",
        0x0006 => "CLASS_DEF", 0x1000 => "MAP_LIST", 0x1001 => "TYPE_LIST",
        0x1002 => "ANNO_SET_REF", 0x1003 => "ANNO_SET", 0x2000 => "CLASS_DATA",
        0x2001 => "CODE_ITEM", 0x2002 => "STRING_DATA", 0x2003 => "DEBUG_INFO",
        0x2004 => "ANNOTATION", 0x2005 => "ENC_ARRAY", 0x2006 => "ANNO_DIR",
        _ => "UNKNOWN",
    };

    let mut out = format!("MAP ({} sections, dex_size={}):\n", sects.len(), dex.len());
    for i in 0..sects.len() {
        let (t, c, o) = sects[i];
        let next_o = if i+1 < sects.len() { sects[i+1].2 } else { dex.len() };
        let computed_end = map_section_end(dex, t, o, c);
        let (gap_bytes, nz_count) = if let Some(end) = computed_end {
            let gap_end = next_o.min(dex.len());
            if end < gap_end {
                let nz: usize = dex[end..gap_end].iter().filter(|&&b| b != 0).count();
                (gap_end - end, nz)
            } else { (0, 0) }
        } else { (0, 0) };
        let end_str = match computed_end {
            Some(e) => format!("{:#x}", e),
            None    => "?".to_string(),
        };
        out += &format!(
            "  {:#08x} {:<12} cnt={:3}  end={}  gap={} nonzero={}\n",
            o, type_name(t), c, end_str, gap_bytes, nz_count
        );
    }
    out
}

/// Return diagnostic info about a method's code_item (registers, tries, insns, offset).
pub fn describe_code_item(dex: &[u8], class_sig: &str, method_name: &str) -> String {
    match find_code_item_off(dex, class_sig, method_name) {
        Ok(off) if off + 16 <= dex.len() => {
            let regs      = r16(dex, off);
            let ins_size  = r16(dex, off + 2);
            let outs_size = r16(dex, off + 4);
            let tries     = r16(dex, off + 6);
            let insns_sz  = r32(dex, off + 12);
            format!("code_item@{:#x}: regs={} ins={} outs={} tries={} insns_size={}",
                off, regs, ins_size, outs_size, tries, insns_sz)
        }
        Ok(off) => format!("code_item@{:#x} but DEX too short", off),
        Err(e)  => format!("describe_code_item: {}", e),
    }
}

/// Verify the Adler-32 checksum stored in the DEX header against a recomputed value.
/// Returns (stored, computed) — they should be equal for a valid DEX.
pub fn check_adler32(dex: &[u8]) -> (u32, u32) {
    if dex.len() < 12 { return (0, 0); }
    let stored = u32::from_le_bytes(dex[8..12].try_into().unwrap_or([0;4]));
    let computed = adler32(&dex[12..]);
    (stored, computed)
}

// ---------------------------------------------------------------------------
// Single-class narrowing
// ---------------------------------------------------------------------------

/// Android ART's JVMTI `RedefineClasses` requires a DEX with exactly one
/// `class_def_item`.  When the original DEX has multiple classes we "narrow"
/// it in-place:
///
/// 1. Find the target class_def in the class_defs array.
/// 2. Copy it to position 0 of the array (overwriting whatever was there).
/// 3. Set `class_defs_size` = 1 in the header.
/// 4. Find the TYPE_CLASS_DEF_ITEM entry in the map section and set its
///    `size` field to 1 as well (keeps the map consistent with the header).
///
/// The orphaned class_def bytes are subsequently zeroed by `zero_inter_section_padding`.
fn narrow_to_single_class(data: &mut Vec<u8>, class_sig: &str) -> Result<(), PatchError> {
    if data.len() < 112 {
        return Err(PatchError::Truncated("header"));
    }

    let string_ids_off  = r32(data, 60) as usize;
    let type_ids_off    = r32(data, 68) as usize;
    let class_defs_size = r32(data, 96) as usize;
    let class_defs_off  = r32(data, 100) as usize;
    let map_off         = r32(data, 52) as usize;

    // Already a single-class DEX — nothing to do.
    if class_defs_size <= 1 {
        return Ok(());
    }

    // Find the target class_def index.
    let mut target_idx: Option<usize> = None;
    for i in 0..class_defs_size {
        let def = class_defs_off + i * 32;
        if def + 32 > data.len() { break; }
        let class_idx  = r32(data, def) as usize;
        let type_off   = type_ids_off + class_idx * 4;
        if type_off + 4 > data.len() { continue; }
        let string_idx = r32(data, type_off);
        if let Some(sig) = read_string(data, string_ids_off, string_idx) {
            if sig == class_sig {
                target_idx = Some(i);
                break;
            }
        }
    }

    let idx = target_idx.ok_or(PatchError::ClassNotFound)?;

    // Move target class_def to index 0 if it isn't already there.
    if idx != 0 {
        let src = class_defs_off + idx * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[src..src + 32]);
        data[class_defs_off..class_defs_off + 32].copy_from_slice(&buf);
    }

    // Set class_defs_size = 1 in the header.
    w32(data, 96, 1);

    // Update data_off and data_size so that the data section begins immediately
    // after the (now single) class_def entry.
    //
    // The original DEX has data_off = class_defs_off + original_class_defs_size * 32
    // (the data section starts right after the class_defs table).  After narrowing,
    // class_defs_size = 1, so ART's verifier expects data_off to be
    // class_defs_off + 32.  Leaving data_off at the old value causes
    // JVMTI_ERROR_INVALID_CLASS_FORMAT (err=60) because data_off no longer
    // equals class_defs_off + class_defs_size * sizeof(ClassDef).
    {
        let new_data_off = class_defs_off as u32 + 32; // one ClassDef = 32 bytes
        let file_size    = r32(data, 32);
        let new_data_size = file_size.saturating_sub(new_data_off);
        w32(data, 108, new_data_off);   // data_off  at header offset 108
        w32(data, 104, new_data_size);  // data_size at header offset 104
    }

    // Read class_def[0].class_data_off (the target class's class_data offset).
    // Used below to update the CLASS_DATA MAP entry.
    let target_class_data_off = r32(data, class_defs_off + 24) as usize;

    // Update the map section.  We need to fix two entries:
    //
    //  1. TYPE_CLASS_DEF_ITEM (0x0006): count → 1
    //     ART's JVMTI RedefineClasses requires NumClassDefs() == 1.
    //
    //  2. TYPE_CLASS_DATA_ITEM (0x2000): count → 1, offset → target_class_data_off
    //     ART's DexFileVerifier::CheckInterSection walks every class_data item and
    //     verifies it is referenced by exactly one class_def.  With 20 orphaned
    //     class_data items (from the other classes) the check fails:
    //     "Could not find declaring class for non-empty class data item."
    //     Setting count=1 and offset=target class_data ensures only the target
    //     class's class_data is validated.  zero_inter_section_padding (called
    //     next) will zero the former class_data bytes that are now in the gap.
    if map_off + 4 <= data.len() {
        let map_list_size = r32(data, map_off) as usize;
        for i in 0..map_list_size {
            let item = map_off + 4 + i * 12;
            if item + 12 > data.len() { break; }
            let item_type = u16::from_le_bytes(data[item..item + 2].try_into().unwrap());
            match item_type {
                0x0006 => {  // TYPE_CLASS_DEF_ITEM
                    w32(data, item + 4, 1);
                }
                0x2000 => {  // TYPE_CLASS_DATA_ITEM
                    w32(data, item + 4, 1);                           // count = 1
                    if target_class_data_off != 0 {
                        w32(data, item + 8, target_class_data_off as u32);  // offset
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DEX layout helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u16 from `data[off..off+2]`.
#[inline]
fn r16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

/// Read a little-endian u32 from `data[off..off+4]`.
#[inline]
fn r32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

/// Write a little-endian u16 to `data[off..off+2]`.
#[inline]
fn w16(data: &mut [u8], off: usize, val: u16) {
    data[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 to `data[off..off+4]`.
#[inline]
fn w32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

/// Read an unsigned LEB128 value, advancing `*pos`.
fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() { return None; }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 { return Some(result); }
        shift += 7;
        if shift >= 35 { return None; }
    }
}

/// Resolve string_ids[idx] → the MUTF-8 string content as a str slice.
fn read_string<'a>(data: &'a [u8], string_ids_off: usize, idx: u32) -> Option<&'a str> {
    let id_off = string_ids_off.checked_add(idx as usize * 4)?;
    if id_off + 4 > data.len() { return None; }
    let str_data_off = r32(data, id_off) as usize;
    if str_data_off >= data.len() { return None; }

    let mut pos = str_data_off;
    loop {
        if pos >= data.len() { return None; }
        let b = data[pos]; pos += 1;
        if b & 0x80 == 0 { break; }
    }
    let start = pos;
    while pos < data.len() && data[pos] != 0 { pos += 1; }
    std::str::from_utf8(&data[start..pos]).ok()
}

// ---------------------------------------------------------------------------
// Core: find the byte offset of a method's code_item
// ---------------------------------------------------------------------------

fn find_code_item_off(data: &[u8], class_sig: &str, method_name: &str)
    -> Result<usize, PatchError>
{
    if data.len() < 112 {
        return Err(PatchError::Truncated("header"));
    }
    if &data[0..4] != b"dex\n" || data[7] != 0 {
        return Err(PatchError::InvalidMagic);
    }

    let string_ids_off  = r32(data, 60) as usize;
    let type_ids_off    = r32(data, 68) as usize;
    let method_ids_off  = r32(data, 92) as usize;
    let class_defs_size = r32(data, 96) as usize;
    let class_defs_off  = r32(data, 100) as usize;

    let mut class_data_off: usize = 0;
    'class_search: for i in 0..class_defs_size {
        let def = class_defs_off + i * 32;
        if def + 32 > data.len() { break; }
        let class_idx = r32(data, def) as usize;
        let type_off  = type_ids_off + class_idx * 4;
        if type_off + 4 > data.len() { continue; }
        let string_idx = r32(data, type_off);
        if let Some(sig) = read_string(data, string_ids_off, string_idx) {
            if sig == class_sig {
                let cdo = r32(data, def + 24) as usize;
                class_data_off = cdo;
                break 'class_search;
            }
        }
    }

    if class_data_off == 0 {
        let mut found = false;
        for i in 0..class_defs_size {
            let def = class_defs_off + i * 32;
            if def + 32 > data.len() { break; }
            let class_idx  = r32(data, def) as usize;
            let type_off   = type_ids_off + class_idx * 4;
            if type_off + 4 > data.len() { continue; }
            let string_idx = r32(data, type_off);
            if let Some(sig) = read_string(data, string_ids_off, string_idx) {
                if sig == class_sig { found = true; break; }
            }
        }
        return if found {
            Err(PatchError::MethodNotFound)
        } else {
            Err(PatchError::ClassNotFound)
        };
    }

    let mut pos = class_data_off;
    let static_fields_size   = read_uleb128(data, &mut pos)
        .ok_or(PatchError::Truncated("class_data counts"))?;
    let instance_fields_size = read_uleb128(data, &mut pos)
        .ok_or(PatchError::Truncated("class_data counts"))?;
    let direct_methods_size  = read_uleb128(data, &mut pos)
        .ok_or(PatchError::Truncated("class_data counts"))?;
    let virtual_methods_size = read_uleb128(data, &mut pos)
        .ok_or(PatchError::Truncated("class_data counts"))?;

    for _ in 0..static_fields_size {
        read_uleb128(data, &mut pos); read_uleb128(data, &mut pos);
    }
    for _ in 0..instance_fields_size {
        read_uleb128(data, &mut pos); read_uleb128(data, &mut pos);
    }

    let mut method_idx: u32 = 0;
    let total = direct_methods_size + virtual_methods_size;

    for j in 0..total {
        if j == direct_methods_size { method_idx = 0; }

        let diff = read_uleb128(data, &mut pos)
            .ok_or(PatchError::Truncated("encoded_method idx"))?;
        method_idx = method_idx.wrapping_add(diff);

        let _access_flags = read_uleb128(data, &mut pos)
            .ok_or(PatchError::Truncated("encoded_method flags"))?;
        let code_off = read_uleb128(data, &mut pos)
            .ok_or(PatchError::Truncated("encoded_method code_off"))? as usize;

        let mid = method_ids_off + method_idx as usize * 8;
        if mid + 8 > data.len() { continue; }
        let name_idx = r32(data, mid + 4);

        if let Some(name) = read_string(data, string_ids_off, name_idx) {
            if name == method_name {
                if code_off == 0 {
                    return Err(PatchError::NoCodeItem);
                }
                return Ok(code_off);
            }
        }
    }

    Err(PatchError::MethodNotFound)
}

// ---------------------------------------------------------------------------
// Patch implementations
// ---------------------------------------------------------------------------

/// Overwrite the code_item for (class_sig, method_name) with `payload`.
fn apply_return_patch(
    data: &mut Vec<u8>,
    class_sig: &str,
    method_name: &str,
    payload: &[u16],
) -> Result<(), PatchError> {
    let code_off = find_code_item_off(data, class_sig, method_name)?;

    // code_item layout:
    //  +0   u16  registers_size
    //  +2   u16  ins_size
    //  +4   u16  outs_size
    //  +6   u16  tries_size
    //  +8   u32  debug_info_off
    //  +12  u32  insns_size   (code units)
    //  +16  u16  insns[insns_size]

    if code_off + 16 > data.len() {
        return Err(PatchError::Truncated("code_item header"));
    }

    let existing_regs  = r16(data, code_off) as u32;
    let existing_units = r32(data, code_off + 12) as usize;

    if code_off + 16 + existing_units * 2 > data.len() {
        return Err(PatchError::Truncated("code_item insns"));
    }

    let payload_units = payload.len();
    if payload_units > existing_units {
        return Err(PatchError::PayloadTooLarge {
            need: payload_units,
            have: existing_units,
        });
    }

    // Bump registers_size to at least 1 if the payload uses v0.
    let needs_v0 = payload_units > 1
        || (payload_units == 1 && payload[0] != 0x000e);  // not pure return-void
    if needs_v0 && existing_regs == 0 {
        w16(data, code_off, 1);
    }

    // IMPORTANT: do NOT change insns_size or tries_size.
    //
    // ART's DEX structural verifier walks code_items sequentially, computing
    // each item's byte length from insns_size + tries_size.  Shrinking
    // insns_size shifts the verifier's cursor into the middle of the next
    // code_item's bytes → it reads garbage → JVMTI_ERROR_INVALID_CLASS_FORMAT.
    // Similarly clearing tries_size when the original had try/catch blocks
    // loses the handlers bytes from the size calculation.
    //
    // Solution: keep insns_size = existing_units and tries_size as-is.
    // Write the payload at instructions 0..payload_units, then nop-pad the
    // remainder.  The code_item's byte footprint is unchanged.

    // Write payload code units at the start of insns[].
    let insns_base = code_off + 16;
    for (i, &unit) in payload.iter().enumerate() {
        w16(data, insns_base + i * 2, unit);
    }

    // Nop-pad instructions payload_units..existing_units.
    for i in payload_units..existing_units {
        w16(data, insns_base + i * 2, 0x0000);
    }

    Ok(())
}

/// Write 0x0000 (nop) over `width` code units starting at `offset` within
/// the named method's insns array. Does not change insns_size.
fn apply_nop_patch(
    data: &mut Vec<u8>,
    class_sig: &str,
    method_name: &str,
    offset: u32,
    width: u32,
) -> Result<(), PatchError> {
    let code_off = find_code_item_off(data, class_sig, method_name)?;

    if code_off + 16 > data.len() {
        return Err(PatchError::Truncated("code_item header"));
    }

    let insns_size = r32(data, code_off + 12);
    if offset + width > insns_size {
        return Err(PatchError::PayloadTooLarge {
            need: (offset + width) as usize,
            have: insns_size as usize,
        });
    }

    let insns_base = code_off + 16;
    let byte_start = insns_base + offset as usize * 2;
    let byte_end   = byte_start + width as usize * 2;

    if byte_end > data.len() {
        return Err(PatchError::Truncated("insns nop range"));
    }

    for b in &mut data[byte_start..byte_end] {
        *b = 0;
    }

    Ok(())
}

/// Write a goto instruction at `from_bci` within the named method's insns array,
/// then nop-pad the rest of the original instruction's width.
fn apply_goto_patch(
    data: &mut Vec<u8>,
    class_sig: &str,
    method_name: &str,
    from_bci: u32,
    payload: &[u16],
    instr_width: u32,
) -> Result<(), PatchError> {
    let code_off = find_code_item_off(data, class_sig, method_name)?;

    if code_off + 16 > data.len() {
        return Err(PatchError::Truncated("code_item header"));
    }

    let insns_size = r32(data, code_off + 12);
    if from_bci >= insns_size {
        return Err(PatchError::PayloadTooLarge {
            need: from_bci as usize + 1,
            have: insns_size as usize,
        });
    }

    let insns_base = code_off + 16;

    // Write the goto payload at from_bci.
    for (i, &unit) in payload.iter().enumerate() {
        let byte_off = insns_base + (from_bci as usize + i) * 2;
        if byte_off + 2 > data.len() {
            return Err(PatchError::Truncated("insns goto range"));
        }
        w16(data, byte_off, unit);
    }

    // Nop-pad the rest of the original instruction's slot so insn boundaries are preserved.
    for i in payload.len()..instr_width as usize {
        let byte_off = insns_base + (from_bci as usize + i) * 2;
        if byte_off + 2 <= data.len() {
            w16(data, byte_off, 0x0000);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DEX checksum/signature fixup
// ---------------------------------------------------------------------------

fn fix_checksums(data: &mut Vec<u8>) {
    if data.len() < 32 { return; }
    let sig = sha1(&data[32..]);
    data[12..32].copy_from_slice(&sig);
    let cksum = adler32(&data[12..]);
    data[8..12].copy_from_slice(&cksum.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Adler-32
// ---------------------------------------------------------------------------

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &byte in data {
        s1 = (s1 + byte as u32) % MOD;
        s2 = (s2 + s1) % MOD;
    }
    (s2 << 16) | s1
}

// ---------------------------------------------------------------------------
// SHA-1 (inline, no external dependency)
// ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k): (u32, u32) = match i {
                0..=19  => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d,             0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _       => (b ^ c ^ d,             0xCA62C1D6),
            };
            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_empty() {
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn adler32_known() {
        let val = adler32(b"Wikipedia");
        assert_eq!(val, 0x11E60398);
    }

    #[test]
    fn sha1_known() {
        let h = sha1(b"");
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_abc() {
        let h = sha1(b"abc");
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn uleb128_single_byte() {
        let data = [0x05u8];
        let mut pos = 0usize;
        assert_eq!(read_uleb128(&data, &mut pos), Some(5u32));
        assert_eq!(pos, 1);
    }

    #[test]
    fn uleb128_multi_byte() {
        let data = [0xAC, 0x02];
        let mut pos = 0usize;
        assert_eq!(read_uleb128(&data, &mut pos), Some(300u32));
        assert_eq!(pos, 2);
    }
}
