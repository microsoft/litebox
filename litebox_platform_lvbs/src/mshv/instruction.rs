#![allow(unused, dead_code)]
use crate::serial_println;
use hashbrown::HashMap;
use litebox_common_linux::errno::Errno;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use once_cell::race::OnceBox;
use x86_64::VirtAddr;

static INSN_NOP: [&[u8]; 6] = [
    &[0x90],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
];

#[repr(u8)]
#[derive(PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
pub enum Opcode {
    TwoByteEscape = 0x0F,
    EsSegOverride = 0x26,
    CsSegOverride = 0x2E,
    SsSegOverride = 0x36,
    ThreeByteEscape38 = 0x38,
    ThreeByteEscape3A = 0x3A,
    DsSegOverride = 0x3E,
    Rex40 = 0x40,
    Rex41,
    Rex42,
    Rex43,
    Rex44,
    Rex45,
    Rex46,
    Rex47,
    Rex48,
    Rex49,
    Rex4a,
    Rex4b,
    Rex4c,
    Rex4d,
    Rex4e,
    Rex4f = 0x4F,
    FsSegOverride = 0x64,
    GsSegOverride = 0x65,
    OperandOverride = 0x66,
    AddressOverride = 0x67,
    RetNear = 0xC3,
    Int3 = 0xCC,
    //const OPCODE_NOP: u8 = 0x90;
    CallRel32 = 0xE8,
    JmpRel32 = 0xE9,
    Lock = 0xF0,
    Repne = 0xF2,
    Repe = 0xF3,
    //const OPCODE_CALL_RM64: u8 = 0xFF;
}

impl Opcode {
    fn size(&self) -> usize {
        let Some(OpcodeType::Opcode(attr)) = get_opcodes().get(self) else {
            return 0;
        };
        attr.get_size()
    }
}

fn testme() -> usize {
    Opcode::AddressOverride.size()
}
static OPCODES: OnceBox<HashMap<Opcode, OpcodeType>> = OnceBox::new();

fn get_opcodes() -> &'static HashMap<Opcode, OpcodeType> {
    //static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    OPCODES.get_or_init(|| {
        let mut h = HashMap::new();
        h.insert(Opcode::TwoByteEscape, OpcodeType::Escape);
        h.insert(Opcode::EsSegOverride, OpcodeType::SegmentOverride);
        h.insert(Opcode::CsSegOverride, OpcodeType::SegmentOverride);
        h.insert(Opcode::SsSegOverride, OpcodeType::SegmentOverride);

        h.insert(Opcode::ThreeByteEscape38, OpcodeType::Escape);
        h.insert(Opcode::ThreeByteEscape3A, OpcodeType::Escape);

        h.insert(Opcode::DsSegOverride, OpcodeType::SegmentOverride);

        let rex_start: u8 = Opcode::Rex40.into();
        let rex_end: u8 = Opcode::Rex4f.into();
        for rex_opcode in rex_start..rex_end {
            h.insert(Opcode::try_from(rex_opcode).unwrap(), OpcodeType::Rex);
        }

        h.insert(Opcode::FsSegOverride, OpcodeType::SegmentOverride);
        h.insert(Opcode::GsSegOverride, OpcodeType::SegmentOverride);
        h.insert(Opcode::OperandOverride, OpcodeType::OperandSizeOverride);
        h.insert(Opcode::AddressOverride, OpcodeType::AddrSizeOverride);

        h.insert(
            Opcode::CallRel32,
            OpcodeType::Opcode(OpcodeAttr::new().with_imm(4).with_f64().with_size(5)),
        );

        h.insert(
            Opcode::RetNear,
            OpcodeType::Opcode(OpcodeAttr::new().with_f64().with_size(1)),
        );

        h.insert(
            Opcode::Int3,
            OpcodeType::Opcode(OpcodeAttr::new().with_size(1)),
        );

        h.insert(
            Opcode::JmpRel32,
            OpcodeType::Opcode(OpcodeAttr::new().with_imm(4).with_f64().with_size(5)),
        );

        h.insert(Opcode::Lock, OpcodeType::LockRepeat);
        h.insert(Opcode::Repne, OpcodeType::LockRepeat);
        h.insert(Opcode::Repe, OpcodeType::LockRepeat);

        alloc::boxed::Box::new(h)
    })
}

#[derive(Copy, Clone, PartialEq)]
struct OpcodeAttr(u64);

impl OpcodeAttr {
    const IMM_BITFIELD_POS: usize = 0;
    const IMM_BITFIELD_START: u64 = 0;
    const IMM_BITFIELD_END: u64 = 2;

    const F64_BITFIELD_POS: usize = 1;
    const F64_BITFIELD_START: u64 = 3;
    const F64_BITFIELD_END: u64 = 3;

    const MODRM_BITFIELD_POS: usize = 2;
    const MODRM_BITFIELD_START: u64 = 4;
    const MODRM_BITFIELD_END: u64 = 4;

    const GROUP_BITFIELD_POS: usize = 3;
    const GROUP_BITFIELD_START: u64 = 5;
    const GROUP_BITFIELD_END: u64 = 9;

    const SIZE_BITFIELD_POS: usize = 4;
    const SIZE_BITFIELD_START: u64 = 10;
    const SIZE_BITFIELD_END: u64 = 13;

    const ESC_BITFIELD_POS: usize = 5;
    const ESC_BITFIELD_START: u64 = 14;
    const ESC_BITFIELD_END: u64 = 14;

    const BITFIELD_BOUNDS: [(u64, u64); 6] = [
        (Self::IMM_BITFIELD_START, Self::IMM_BITFIELD_END),
        (Self::F64_BITFIELD_START, Self::F64_BITFIELD_END),
        (Self::MODRM_BITFIELD_START, Self::MODRM_BITFIELD_END),
        (Self::GROUP_BITFIELD_START, Self::GROUP_BITFIELD_END),
        (Self::SIZE_BITFIELD_START, Self::SIZE_BITFIELD_END),
        (Self::ESC_BITFIELD_START, Self::ESC_BITFIELD_END),
    ];

    fn new() -> Self {
        Self(0)
    }

    /*fn new(imm: usize, f64: bool, modrm: bool, group: usize) -> Self {
        let mut attr = OpcodeAttr(0);
        OpcodeAttr::set_imm(&mut attr, imm);
        OpcodeAttr::set_f64(&mut attr, f64);
        OpcodeAttr::set_modrm(&mut attr, modrm);
        OpcodeAttr::set_group(&mut attr, group);
        attr
    }*/

    fn set_mask(start: u64, end: u64) -> u64 {
        (1u64 << (end - start + 1)) - 1
    }

    fn get_mask(start: u64, end: u64) -> u64 {
        Self::set_mask(start, end) << start
    }

    fn with_imm(mut self, imm: usize) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::IMM_BITFIELD_POS];
        self.0 |= ((imm as u64) & Self::set_mask(start, end)) << start;
        self
    }

    fn get_imm(self) -> usize {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::IMM_BITFIELD_POS];
        usize::try_from((self.0 & Self::get_mask(start, end)) >> start).unwrap()
    }

    fn with_f64(mut self) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::F64_BITFIELD_POS];
        self.0 |= (1 & Self::set_mask(start, end)) << start;
        self
    }

    fn get_f64(self) -> bool {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::F64_BITFIELD_POS];
        ((self.0 & Self::get_mask(start, end)) >> start) != 0
    }

    fn with_modrm(mut self, modrm: bool) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::MODRM_BITFIELD_POS];
        self.0 |= ((u64::from(modrm)) & Self::set_mask(start, end)) << start;
        self
    }

    fn get_modrm(self) -> bool {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::MODRM_BITFIELD_POS];
        ((self.0 & Self::get_mask(start, end)) >> start) != 0
    }

    fn with_group(mut self, group: usize) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::GROUP_BITFIELD_POS];
        self.0 |= ((group as u64) & Self::set_mask(start, end)) << start;
        self
    }

    fn get_group(self) -> usize {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::GROUP_BITFIELD_POS];
        usize::try_from((self.0 & Self::get_mask(start, end)) >> start).unwrap()
    }

    fn with_size(mut self, size: usize) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::SIZE_BITFIELD_POS];
        self.0 |= ((size as u64) & Self::set_mask(start, end)) << start;
        self
    }

    fn get_size(self) -> usize {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::SIZE_BITFIELD_POS];
        usize::try_from((self.0 & Self::get_mask(start, end)) >> start).unwrap()
    }

    fn with_esc(mut self) -> Self {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::ESC_BITFIELD_POS];
        self.0 |= (1 & Self::set_mask(start, end)) << start;
        self
    }

    fn get_esc(self) -> bool {
        let (start, end) = Self::BITFIELD_BOUNDS[Self::ESC_BITFIELD_POS];
        (self.0 & Self::get_mask(start, end)) >> start != 0
    }
}

#[derive(Copy, Clone, PartialEq)]
enum OpcodeType {
    LockRepeat,
    SegmentOverride,
    OperandSizeOverride,
    AddrSizeOverride,
    Rex,
    Escape,
    Opcode(OpcodeAttr),
}

struct InstructionField {
    value: i32,
    size: usize,
}

pub struct Instruction<'a> {
    bytes: &'a [u8],
    prefix_count: usize,
    operand_size: u8,
    addr_size: u8,
    pos: usize,
    opcode: Option<u8>,
    escape: Option<u8>,
    attr: Option<OpcodeAttr>,
    imm: Option<InstructionField>,
    // 2.2.1.3 ModR/M and SIB remain 8 or 32 bits, sign extended to 64 bits in 64-bit mode
    mod_rm: Option<InstructionField>,
    sib: Option<InstructionField>,
    disp: Option<InstructionField>,
    rex: Option<u8>, //0 - 3 operands can be idenifiier(regs or identified data) or literal
}

impl<'a> Instruction<'a> {
    const MAX_INSN_SIZE: usize = 15;
    pub fn from(bytes: &'a [u8]) -> Self {
        //serial_println!("Instr: {:x?}", bytes);
        Instruction {
            bytes,
            prefix_count: 0,
            operand_size: 4,
            addr_size: 8, //2.2.1.4 default to 64 bits in 64-bit mode
            pos: 0,
            opcode: None,
            escape: None,
            attr: None,
            imm: None,
            mod_rm: None,
            sib: None,
            disp: None,
            rex: None,
        }
    }

    pub fn decode(&mut self) -> Result<(), Errno> {
        serial_println!("Decoding...");
        self.decode_legacy_prefix()?;
        self.decode_rex()?;
        self.decode_opcode()?;
        self.decode_modrm()?;
        self.decode_sib()?;
        self.decode_disp()?;
        self.decode_imm()?;
        Ok(())
    }

    pub fn length(&self) -> usize {
        self.pos
    }

    pub fn opcode(&self) -> Option<u8> {
        self.opcode
    }

    pub fn imm(&self) -> Option<i32> {
        //if let Some(imm) = self.imm.as_ref() {
        //    Some(imm.value)
        //} else {
        //    None
        //}
        self.imm.as_ref().map(|imm| imm.value)
    }

    fn decode_legacy_prefix(&mut self) -> Result<(), Errno> {
        while let opcode_type @ Some(
            OpcodeType::LockRepeat
            | OpcodeType::SegmentOverride
            | OpcodeType::OperandSizeOverride
            | OpcodeType::AddrSizeOverride,
        ) = get_opcodes().get(&Opcode::try_from(self.peek_byte()?).unwrap())
        {
            let prefix = self.read_byte()?;
            serial_println!("Found prefix: {:02x}", prefix);
            if self.bytes[0..self.prefix_count].contains(&prefix) {
                return Err(Errno::EINVAL);
            }
            self.prefix_count += 1;

            match opcode_type.unwrap() {
                //Will always be Some()
                OpcodeType::OperandSizeOverride => self.operand_size ^= 0xC,
                OpcodeType::AddrSizeOverride => self.addr_size ^= 0x6,
                _ => {}
            }
        }
        Ok(())
    }

    fn decode_rex(&mut self) -> Result<(), Errno> {
        let Some(OpcodeType::Rex) =
            get_opcodes().get(&Opcode::try_from(self.peek_byte()?).unwrap())
        else {
            return Ok(());
        };
        let rex = self.read_byte()?;
        serial_println!("Found rex: {:02x}", rex);
        if rex & 0x8 != 0 {
            self.operand_size = 8;
        }
        self.rex = Some(rex);
        Ok(())
    }

    fn decode_opcode(&mut self) -> Result<(), Errno> {
        let mut opcode = self.read_byte()?;
        serial_println!("Found opcode: {:02x}", opcode);

        let mut has_escape = false;

        while let Some(&OpcodeType::Escape) = get_opcodes().get(&Opcode::try_from(opcode).unwrap())
        {
            if opcode != Opcode::TwoByteEscape.into() || has_escape {
                // We only support escape code 0xF0
                return Err(Errno::EINVAL);
            }
            has_escape = true;
            self.escape = Some(opcode);
            opcode = self.read_byte()?;
        }

        let Some(&OpcodeType::Opcode(attr)) = get_opcodes().get(&Opcode::try_from(opcode).unwrap())
        else {
            return Err(Errno::EINVAL);
        };

        self.opcode = Some(opcode);
        if has_escape {
           self.attr = Some(attr.with_esc());
        } else {
            self.attr = Some(attr);
        }
        Ok(())
    }

    fn decode_modrm(&mut self) -> Result<(), Errno> {
        let Some(attr) = self.attr else {
            return Err(Errno::EINVAL);
        };
        let modrm = attr.get_modrm();
        if modrm {
            self.mod_rm = Some(self.read_field(1)?);
            serial_println!("Found modrm: {:02x}", self.mod_rm.as_ref().unwrap().value);
        }
        // get group from attr and pase. not supported
        // the only op supported e8 doesnt have this, so...

        //check f64 after all other attrs
        if attr.get_f64() {
            self.operand_size = 8;
        }
        Ok(())
    }

    fn decode_sib(&mut self) -> Result<(), Errno> {
        let Some(mod_rm) = &self.mod_rm else {
            return Ok(());
        };
        if mod_rm.size == 0 {
            return Ok(());
        }
        let mod_ = (mod_rm.value & 0xC0) >> 6;
        //let _reg_opcode = (mod_rm.value & 0x38) >> 3;
        let rm = mod_rm.value & 0x07;

        if mod_ != 3 && rm == 4 {
            self.sib = Some(self.read_field(1)?);
            serial_println!("Found sib: {:02x}", self.sib.as_ref().unwrap().value);
        }
        Ok(())
    }

    fn decode_disp(&mut self) -> Result<(), Errno> {
        let Some(mod_rm) = &self.mod_rm else {
            return Ok(());
        };
        if mod_rm.size == 0 {
            return Ok(());
        }
        let mod_ = (mod_rm.value & 0xC0) >> 6;
        //let _reg_opcode = (mod_rm.value & 0x38) >> 3;
        let rm = mod_rm.value & 0x07;

        self.disp = match mod_ {
            0 => {
                if rm == 5 {
                    Some(self.read_field(4)?)
                } else {
                    None
                }
            }
            1 => Some(self.read_field(1)?),
            2 => Some(self.read_field(4)?),
            3 => None,
            _ => return Err(Errno::EINVAL),
        };
        serial_println!("Found disp: {:02x}", self.disp.as_ref().unwrap().value);
        Ok(())
    }

    fn decode_imm(&mut self) -> Result<(), Errno> {
        let Some(attr) = self.attr else {
            return Err(Errno::EINVAL);
        };
        let imm = attr.get_imm();
        if imm != 0 {
            self.imm = Some(self.read_field(imm)?);
            serial_println!("Found imm: {:02x}", self.imm.as_ref().unwrap().value);
        }
        Ok(())
    }

    fn read_bytes(&mut self, size: usize) -> Result<i32, Errno> {
        if (self.pos + size) > Self::MAX_INSN_SIZE {
            return Err(Errno::ENOMEM);
        }
        let value = match size {
            1 => i32::from(self.read_byte()?.cast_signed()),
            2 => {
                let mut bytes = [0u8; 2];
                for byte in &mut bytes {
                    *byte = self.read_byte()?;
                }
                i32::from(u16::from_le_bytes(bytes).cast_signed())
            }
            4 => {
                let mut bytes = [0u8; 4];
                for byte in &mut bytes {
                    *byte = self.read_byte()?;
                }
                u32::from_le_bytes(bytes).cast_signed()
            }
            _ => return Err(Errno::EINVAL),
        };
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8, Errno> {
        if self.pos >= Self::MAX_INSN_SIZE {
            return Err(Errno::EINVAL);
        }
        let byte = self.bytes[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn peek_byte(&mut self) -> Result<u8, Errno> {
        if self.pos >= Self::MAX_INSN_SIZE {
            return Err(Errno::EINVAL);
        }
        let byte = self.bytes[self.pos];
        Ok(byte)
    }

    fn read_field(&mut self, size: usize) -> Result<InstructionField, Errno> {
        Ok(InstructionField {
            value: self.read_bytes(size)?,
            size,
        })
    }
}

pub fn text_gen_insn(
    bytes: &mut [u8],
    opcode: Opcode,
    addr: VirtAddr,
    dest: VirtAddr,
) -> Result<(), Errno> {
    if bytes.is_empty() || bytes.len() != opcode.size() {
        return Err(Errno::E2BIG);
    }
    //let b: u8 = opcode.into();
    bytes[0] = opcode.into();

    if bytes.len() > 1 {
        let disp = dest.as_u64().cast_signed() - (addr.as_u64() + bytes.len() as u64).cast_signed();
        let disp_len = bytes.len() - 1;
        match disp_len {
            2 => &bytes[1..].copy_from_slice(&u16::try_from(disp).unwrap().to_ne_bytes()),
            4 => &bytes[1..].copy_from_slice(&u32::try_from(disp).unwrap().to_ne_bytes()),
            _ => panic!(),
        };
    }
    Ok(())
}

pub fn add_nops(bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut len = 0;
    while len < bytes.len() {
        let nop_len = core::cmp::max(bytes.len(), INSN_NOP.len());
        bytes[len..len + nop_len].copy_from_slice(INSN_NOP[nop_len - 1]);
        len += nop_len;
    }
}
