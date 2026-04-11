use pelite::pe64::{Pe, PeFile, exports::Export, PeView};
use std::ffi::c_void;
use std::arch::asm;
use ntapi::ntpebteb::{PEB};
use ntapi::ntpsapi::PEB_LDR_DATA;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use winapi::shared::ntdef::LIST_ENTRY;
use winapi::shared::ntdef::UNICODE_STRING;


pub unsafe fn get_module_handle(module_name: &str) -> *mut u8
{
    let peb_ptr: *mut PEB;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
    }

    if peb_ptr.is_null() { return std::ptr::null_mut(); }

    let ldr : *mut PEB_LDR_DATA = unsafe { (*peb_ptr).Ldr };
    let list_head = unsafe { &(*ldr).InMemoryOrderModuleList };
    let mut current_node :* mut LIST_ENTRY = unsafe { (*list_head).Flink };
    

    while current_node as *const LIST_ENTRY != list_head as *const LIST_ENTRY {
        // let entry = unsafe { (current_node as *const u8).offset(-16) } as *const LdrDataTableEntry; 
        let entry = unsafe { (current_node as *const u8).offset(-(std::mem::offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as isize)) as *const LDR_DATA_TABLE_ENTRY };

        if (unsafe { (*entry).BaseDllName.Length } != 0) {

            let dll_name_raw = unsafe { (*entry).BaseDllName.Buffer };
            let dll_name_len = unsafe { (*entry).BaseDllName.Length as usize / 2 };

            if !dll_name_raw.is_null() {

                let current_name_slice = unsafe { std::slice::from_raw_parts(dll_name_raw, dll_name_len) };
                let current_name = String::from_utf16_lossy(current_name_slice);

                if current_name.to_lowercase() == module_name.to_lowercase() {
                    // 返回基地址
                    return unsafe { (*entry).DllBase } as *mut u8;
                }

            }

        }

        current_node = unsafe { (*current_node).Flink }; 

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