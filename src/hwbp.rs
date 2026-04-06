#[allow(unused_imports)]

use std::mem;
use std::os::raw::c_void;


use anyhow::{Result, anyhow, Ok};

use ntapi::ntzwapi::{ZwGetContextThread, ZwSetContextThread};
use ntapi::winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, EXCEPTION_SINGLE_STEP};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_CONTINUE_EXECUTION};

const SYSCALL_STUB: [u8; 6] = [
    0x4C, 0x8B, 0xD1, // mov r10, rcx
    0x0F, 0x05, // syscall
    0xC3, // ret
];

static mut SSN_0: u32 = 0;
static mut SSN_1: u32 = 0;
static mut SSN_2: u32 = 0;
static mut SSN_3: u32 = 0;
static mut STUB_ADDR: *mut u8 = std::ptr::null_mut();



unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let info = &*exception_info;
        let record = &*info.ExceptionRecord;
        let ctx = &mut *info.ContextRecord;

        if record.ExceptionCode.0 == EXCEPTION_SINGLE_STEP.0 {
            // let breakpoint_addr = ctx.Dr0;

            if record.ExceptionAddress as u64 == ctx.Dr0 {
                ctx.Rax = SSN_0 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr0 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 0 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr1 {
                ctx.Rax = SSN_1 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr1 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 1 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr2 {
                ctx.Rax = SSN_2 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr2 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 2 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if record.ExceptionAddress as u64 == ctx.Dr3 {
                ctx.Rax = SSN_3 as u64;
                ctx.Rip = STUB_ADDR as u64;
                ctx.Dr3 = 0;
                ctx.Dr7 = set_dr7_bit(ctx.Dr7, 3 << 1, 1, 0);

                return EXCEPTION_CONTINUE_EXECUTION;
            }

        }

        EXCEPTION_CONTINUE_SEARCH
    }

}




pub unsafe fn hwbp_init() -> Result<()> {

    unsafe {

        // Allocate memory for the syscall stub and copy the stub code into it
        let stub_size = SYSCALL_STUB.len();
        let stub_addr = VirtualAlloc(
            None,
            stub_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if stub_addr.is_null() {
            return Err(anyhow!("[ERROR] Failed to allocate memory for syscall stub."));
        }

        std::ptr::copy_nonoverlapping(SYSCALL_STUB.as_ptr(), stub_addr as *mut u8, stub_size);
        STUB_ADDR = stub_addr as *mut u8;

        println!("[INFO] Syscall stub allocated at: 0x{:X}", STUB_ADDR as usize);

        // Add the vectored exception handler
        let handler = AddVectoredExceptionHandler(1, Some(exception_handler));
        if handler.is_null() {
            return Err(anyhow!("[ERROR] Failed to add vectored exception handler."));
        }

        println!("[INFO] Vectored exception handler added successfully.");

    }


    // Placeholder for any initialization logic if needed in the future
    Ok(())
}

pub unsafe fn hwbp_cleanup() -> Result<()> {
    unsafe {
        // Remove the vectored exception handler
        RemoveVectoredExceptionHandler(exception_handler as *const c_void);

        println!("[INFO] Vectored exception handler removed successfully.");

        // Free the allocated memory for the syscall stub
        if !STUB_ADDR.is_null() {
            let _ = VirtualFree(STUB_ADDR as *mut _, 0, windows::Win32::System::Memory::MEM_RELEASE);
            println!("[INFO] Syscall stub memory freed.");
        }

        SSN_0 = 0;
        SSN_1 = 0;
        SSN_2 = 0;
        SSN_3 = 0;
    }

    Ok(())
}

pub enum DR {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

fn set_dr7_bit(current_dr7: u64, start_pos: u32, num_bits: u32, new_value: u64) -> u64 {
    let mask: u64 = if num_bits >= 64 {
        !0u64
    } else {
        (1u64 << num_bits) - 1
    };

    let cleared_dr7 = current_dr7 & !(mask << start_pos);

    let new_dr7 = cleared_dr7 | ((new_value & mask) << start_pos);

    new_dr7
}

unsafe fn set_drbp_register(ctx: &mut CONTEXT, dr: &DR, address: usize) {
    match dr {
        DR::Dr0 => ctx.Dr0 = address as u64,
        DR::Dr1 => ctx.Dr1 = address as u64,
        DR::Dr2 => ctx.Dr2 = address as u64,
        DR::Dr3 => ctx.Dr3 = address as u64,
    }
}

fn dr_to_index(dr: &DR) -> u32 {
    match dr {
        DR::Dr0 => 0,
        DR::Dr1 => 1,
        DR::Dr2 => 2,
        DR::Dr3 => 3,
    }
}

fn dr_to_ssn(dr: &DR, ssn: u32) {
    match dr {
        DR::Dr0 => unsafe { SSN_0 = ssn; },
        DR::Dr1 => unsafe { SSN_1 = ssn; },
        DR::Dr2 => unsafe { SSN_2 = ssn; },
        DR::Dr3 => unsafe { SSN_3 = ssn; },
    }
}

unsafe fn set_dr_with_ssn(dr: &DR, address: *const u8, ssn: u32) -> Result<()> {

    unsafe {

        let mut ctx: CONTEXT = mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let status = ZwGetContextThread(
            HANDLE(-2 as isize as *mut c_void).0 as *mut _,
        &mut ctx as *mut CONTEXT,
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwGetContextThread failed with status: 0x{:X}", status).into());
        }

        set_drbp_register(&mut ctx, &dr, address as usize);

        dr_to_ssn(&dr, ssn);

        let dr_index: u32 = dr_to_index(&dr);
        ctx.Dr7 = set_dr7_bit(ctx.Dr7, dr_index << 1u8, 1, 1);

        let status = ZwSetContextThread(
            HANDLE(-2 as isize as *mut c_void).0 as *mut _,
            &mut ctx as *mut CONTEXT,
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwSetContextThread failed with status: 0x{:X}", status).into());
        }

    }
    

    Ok(())
}


pub unsafe fn set_hwbp(dr: &DR, func_name: &str) -> Result<()> {


    unsafe {

        let ntdll = GetModuleHandleA(PCSTR("ntdll.dll\0".as_ptr()))
            .expect("[ERROR] Failed to get NTDLL.dll handle.");

        let func_addr = GetProcAddress(ntdll, PCSTR(func_name.as_ptr() as *const u8))
            .expect("[ERROR] Failed to get {func_name} address.");

        println!("[INFO] Setting hardware breakpoint on {func_name} at address: 0x{:X}", func_addr as usize);

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        let mut ssn = 0;
        for i in 0..bytes.len().saturating_sub(4) {
            if bytes[i] == 0xB8 {
                ssn = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                break;
            }
        }

        if ssn == 0 {
            return Err(anyhow!("[ERROR] Failed to find syscall number for {func_name}"));
        }

        set_dr_with_ssn(&dr, func_addr as *const u8, ssn)?;

        println!("[INFO] Hardware breakpoint set successfully on {func_name} (SSN: 0x{:X})", ssn);

    }




    Ok(())
}

pub unsafe fn unset_hwbp(dr: &DR) -> Result<()> {

    unsafe {

        let mut ctx: CONTEXT = mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        let status = ZwGetContextThread(
            HANDLE(-2 as isize as *mut c_void).0 as *mut _,
            &mut ctx as *mut CONTEXT,
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwGetContextThread failed with status: 0x{:X}", status).into());
        }

        set_drbp_register(&mut ctx, &dr, 0);

        let dr_index: u32 = dr_to_index(&dr);
        ctx.Dr7 = set_dr7_bit(ctx.Dr7, dr_index << 1u8, 1, 0);

        let status = ZwSetContextThread(
            HANDLE(-2 as isize as *mut c_void).0 as *mut _,
            &mut ctx as *mut CONTEXT,
        );

        if status != 0 {
            return Err(anyhow!("[ERROR] ZwSetContextThread failed with status: 0x{:X}", status).into());
        }

    }

    println!("[INFO] Hardware breakpoint on DR{} unset successfully.", dr_to_index(&dr));

    Ok(())

}
