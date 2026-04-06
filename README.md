# ReflectiveDLL Injector in Rust

Rust实现的反射DLL注入器

## Usage

```
Inject ReflectiveDLL.dll into a target process

Usage: injector-rust.exe [OPTIONS] --process <PROCESS>

Options:
  -p, --process <PROCESS>  Target process name (e.g., notepad.exe)
  -u, --url <URL>          URL to download the DLL from (e.g., http://example.com/ReflectiveDLL.dll)
  -h, --help               Print help
  -V, --version            Print version
```