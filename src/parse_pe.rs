use pelite::pe64::{Pe, PeFile, exports::Export, PeView};
use std::ffi::c_void;
use std::arch::asm;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
pub struct PebLdrData {
    pub reserved: [u8; 8],
    pub reserved2: [u64; 3],
    pub in_memory_order_module_list: ListEntry,
}

#[repr(C)]
pub struct Peb {
    // pub reserved: [u8; 16],
    pub reserved1: [u8; 2],
    pub being_debugged: u8,
    pub reserved2: [u8; 1],
    pub reserved3: [u64; 2],
    pub ldr: *mut PebLdrData,
}

#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: u64,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}


pub unsafe fn get_module_handle(module_name: &str) -> *mut u8
{
    let peb_ptr: *mut Peb;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
    }

    if peb_ptr.is_null() { return std::ptr::null_mut(); }

    let ldr : *mut PebLdrData = unsafe { (*peb_ptr).ldr };
    let list_head : *const ListEntry = unsafe { &(*ldr).in_memory_order_module_list as *const ListEntry };
    let mut current_node :* mut ListEntry = unsafe { (*list_head).flink };
    

    while current_node as *const ListEntry != list_head {
        // let entry = unsafe { (current_node as *const u8).offset(-16) } as *const LdrDataTableEntry; 
        let entry = unsafe { (current_node as *const u8).offset(-(std::mem::offset_of!(LdrDataTableEntry, in_memory_order_links) as isize)) as *const LdrDataTableEntry };

        if (unsafe { (*entry).base_dll_name.length } != 0) {

            let dll_name_raw = unsafe { (*entry).base_dll_name.buffer };
            let dll_name_len = unsafe { (*entry).base_dll_name.length as usize / 2 };

            if !dll_name_raw.is_null() {
                let current_name_slice = unsafe { std::slice::from_raw_parts(dll_name_raw, dll_name_len) };
                let current_name = String::from_utf16_lossy(current_name_slice);

                if current_name.to_lowercase() == module_name.to_lowercase() {
                    // 返回基地址
                    return unsafe { (*entry).dll_base } as *mut u8;
                }

            }

        }

        current_node = unsafe { (*current_node).flink }; 

    }

    std::ptr::null_mut()

}




pub struct PeFileParser<'a> {
    pub data: &'a [u8],
    pub pe: PeFile<'a>,
}

impl<'a> PeFileParser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            data: bytes,
            pe: PeFile::from_bytes(bytes).expect("[ERROR] Failed to initialize PeFile") 
        }
    }


    pub fn get_func_rva(&self, name: &str) -> Option<u32> {
        let exports = self.pe.exports().ok()?;
        let query = exports.by().ok()?;

        match query.name(name).ok()? {
            Export::Symbol(&rva) => Some(rva),
            Export::Forward(_) => {
                eprintln!("Warning: Function '{}' is a forwarded export, skipping RVA retrieval", name);
                None
            }, // 转发导出不返回 RVA

        }
    }

    pub fn get_func_raw(&self, name: &str) -> Option<usize> {
        self.get_func_rva(name)
            .and_then(|rva| self.pe.rva_to_file_offset(rva).ok())
    }
}

pub struct PeModuleParser<'a> {
    pub data: *mut u8,
    pub view: PeView<'a>,
}

impl<'a> PeModuleParser<'a> {
    pub fn new(data: *mut u8) -> Self {
        let view = unsafe { PeView::module(data) };
        Self { data, view }
    }

    pub fn get_func_addr(&self, name: &str) -> Option<*mut u8> {
        let exports = self.view.exports().ok()?;
        let query = exports.by().ok()?;

        match query.name(name).ok()? {
            Export::Symbol(&rva) => {
                unsafe { Some(self.data.add(rva as usize )) }
            }
            Export::Forward(target) => {
                eprintln!("Warning: Function '{}' is forwarded to {:?}, skipping", name, target);
                None
            }
        }
    }
}