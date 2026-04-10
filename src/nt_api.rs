use std::arch::naked_asm;
use std::ffi::c_void;

use ntapi::ntapi_base::CLIENT_ID;
use winapi::um::winnt::{HANDLE, CONTEXT};
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use obfuse::obfuse;
use export_resolver::ExportList;
use anyhow::{self, Error, Ok};






#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_allocate_virtual_memory(process_handle: HANDLE, base_address: *mut *mut c_void, zero_bits: u64, region_size: *mut usize, allocation_type: u64, protect: u64, ssn: u32, syscall_ret: *mut u8) -> i32
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr[rsp+56]",
        "jmp qword ptr[rsp+64]"
    )
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_open_process(process_handle: *mut HANDLE, desired_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES, client_id: *mut CLIENT_ID, ssn: u32, syscall_ret: *mut u8) -> i32
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr[rsp+40]",
        "jmp qword ptr[rsp+48]"
    )

}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_create_thread_ex(thread_handle: *mut HANDLE, desired_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES, process_handle: *mut HANDLE, start_roution: *mut c_void, argument: *mut c_void, create_flags: u64, zero_bits: usize, stack_size: usize, max_stack_size: usize, attribute_list: *mut c_void, ssn: u32, syscall_ret: *mut u8) -> i32
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr[rsp+96]",
        "jmp qword ptr[rsp+104]"
    )
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_write_virtual_memory(process_handle: *mut HANDLE, base_address: *mut c_void, buffer: *mut c_void, number_of_bytes_to_write: usize, number_of_bytes_written: *mut usize, ssn: u32, syscall_ret: *mut u8)
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, dword ptr[rsp+48]",
        "jmp qword ptr[rsp+56]"
    )

}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_get_context_thread(thread_handle: *mut HANDLE, context: *mut CONTEXT, ssn: u32, syscall_ret: *mut u8)
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, r8",
        "jmp r9"
    )

}


#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn zw_set_context_thread(thread_handle: *mut HANDLE, context: *mut CONTEXT, ssn: u32, syscall_ret: *mut u8)
{
    naked_asm!(
        "mov r10, rcx",
        "mov eax, r8",
        "jmp r9"
    )

}


#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NtSsn {
    pub ssn: u32,
    pub syscall_ret: *mut u8,
}

// 实现一个默认初始化，方便创建空数组
impl Default for NtSsn {
    fn default() -> Self {
        Self {
            ssn: 0,
            syscall_ret: std::ptr::null_mut(),
        }
    }
}

#[repr(usize)]
pub enum NtIndex {
    ZwAllocateVirtualMemory = 0,
    ZwProtectVirtualMemory = 1,
    ZwFlushInstructionCache = 2,
    ZwCreateSection = 3,
    ZwMapViewOfSection = 4,
    ZwUnmapViewOfSection = 5,
    ZwQuerySystemInformation = 6,
    ZwQueryObject = 7,
    ZwQueryVirtualMemory = 8,
    ZwFreeVirtualMemory = 9,
    ZwSetContextThread = 10,
    ZwGetContextThread = 11,
    ZwWriteVirtualMemory = 12,
    ZwCreateThreadEx = 13,
    ZwOpenProcess = 14,
}

const NT_FUNCTION_COUNT: usize = 15;

    // pub fn ZwProtectVirtualMemory(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: *mut PVOID,
    //     RegionSize: PSIZE_T,
    //     NewProtect: ULONG,
    //     OldProtect: PULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwFlushInstructionCache(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: PVOID,
    //     NumberOfBytesToFlush: ULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwCreateSection(
    //     SectionHandle: PHANDLE,
    //     DesiredAccess: ACCESS_MASK,
    //     ObjectAttributes: POBJECT_ATTRIBUTES,
    //     MaximumSize: PLARGE_INTEGER,
    //     SectionPageProtection: ULONG,
    //     AllocationAttributes: ULONG,
    //     FileHandle: HANDLE,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwMapViewOfSection(
    //     SectionHandle: HANDLE,
    //     ProcessHandle: HANDLE,
    //     BaseAddress: *mut PVOID,
    //     ZeroBits: SIZE_T,
    //     CommitSize: SIZE_T,
    //     SectionOffset: PLARGE_INTEGER,
    //     ViewSize: PSIZE_T,
    //     InheritDisposition: SECTION_INHERIT,
    //     AllocationType: ULONG,
    //     Protect: ULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwUnmapViewOfSection(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: PVOID,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwQuerySystemInformation(
    //     SystemInformationClass: ULONG,
    //     SystemInformation: PVOID,
    //     SystemInformationLength: ULONG,
    //     ReturnLength: PULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwQueryObject(
    //     Handle: HANDLE,
    //     ObjectInformationClass: ULONG,
    //     ObjectInformation: PVOID,
    //     ObjectInformationLength: ULONG,
    //     ReturnLength: PULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwQueryVirtualMemory(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: PVOID,
    //     MemoryInformationClass: MEMORY_INFORMATION_CLASS,
    //     MemoryInformation: PVOID,
    //     MemoryInformationLength: SIZE_T,
    //     ReturnLength: PSIZE_T,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;

    // pub fn ZwFreeVirtualMemory(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: *mut PVOID,
    //     RegionSize: PSIZE_T,
    //     FreeType: ULONG,
    //     ssn: DWORD,
    //     syscallret: PBYTE,
    // ) -> NTSTATUS;


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


pub fn init_nt_api() -> Result<(), Error>{
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
    let str_zw_get_context_thread = obfused_zw_get_context_thread.as_str();
    let str_zw_set_context_thread = obfused_zw_set_context_thread.as_str();


    let mut exports = ExportList::new();
    exports.add(ntdll_str, str_nt_open_process)?;
    exports.add(ntdll_str, str_nt_allocate_virtual_memory)?;
    exports.add(ntdll_str, str_nt_write_virtual_memory)?;
    exports.add(ntdll_str, str_nt_create_thread_ex)?;
    exports.add(ntdll_str, str_zw_get_context_thread)?;
    exports.add(ntdll_str, str_zw_set_context_thread)?;




    Ok(())
}