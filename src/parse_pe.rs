use pelite::pe64::{Pe, PeFile, exports::Export};

pub struct PeParser {
    pub data: Vec<u8>,
    pe: PeFile<'static>,
}

impl PeParser {
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