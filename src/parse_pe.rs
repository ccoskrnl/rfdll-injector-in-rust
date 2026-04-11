use pelite::pe64::{Pe, PeFile, exports::Export, PeView};

pub struct PeFileParser {
    pub data: Vec<u8>,
    pe: PeFile<'static>,
}

impl PeFileParser {
    pub fn new(bytes: Vec<u8>) -> Self {
        // 将 Vec<u8> 转换为 &'static [u8] 供 PeFile 使用
        // 这里使用 Box::leak 将数据泄漏为静态生命周期，保证 PeFile 可以安全引用
        let data: &'static [u8] = Box::leak(Box::new(bytes));
        let pe = PeFile::from_bytes(data).expect("Failed to parse PE file");
        Self { data: data.to_vec(), pe }
    }


    pub fn get_func_rva(&self, name: &str) -> Option<u32> {
        let exports = self.pe.exports().ok()?;
        let query = exports.by().ok()?;

        match query.name(name).ok()? {
            Export::Symbol(&rva) => Some(rva),
            Export::Forward(_) => {
                eprintln!("Warning: Function '{}' is a forwarded export, skipping RVA retrieval", name);
                None
            }, // 转发导出不返回 RVA

        }
    }

    pub fn get_func_raw(&self, name: &str) -> Option<usize> {
        self.get_func_rva(name).and_then(|rva| self.pe.rva_to_file_offset(rva).ok().map(|offset| offset as usize))
    }
}

pub struct PeModuleParser {
    pub data: *mut u8,
    pub view: PeView<'static>,
}

impl PeModuleParser {
    pub fn new(data: *mut u8) -> Self {
        Self { data, view: PeView::from_bytes(unsafe { std::slice::from_raw_parts(data, 0x1000) }).ok()? }
    }

    pub fn get_func_addr(&self, name: &str) -> Option<*mut u8> {
        let pe = PeFile::from_bytes(unsafe { std::slice::from_raw_parts(self.data, 0x1000) }).ok()?;
        let exports = pe.exports().ok()?;
        let query = exports.by().ok()?;

        match query.name(name).ok()? {
            Export::Symbol(&rva) => Some(unsafe { self.data.add(rva as usize) }),
            Export::Forward(_) => {
                eprintln!("Warning: Function '{}' is a forwarded export, skipping address retrieval", name);
                None
            }, // 转发导出不返回地址
        }
    }
}