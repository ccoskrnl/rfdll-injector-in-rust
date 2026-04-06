# ReflectiveDLL Injector in Rust

Rust实现的反射DLL注入器，使用NTDLL脱钩来绕过EDR

## 使用

```
Inject ReflectiveDLL.dll into a target process

Usage: injector-rust.exe [OPTIONS] --process <PROCESS>

Options:
  -p, --process <PROCESS>  Target process name (e.g., notepad.exe)
  -u, --url <URL>          URL to download the DLL from (e.g., http://example.com/ReflectiveDLL.dll)
      --rflname <RFLNAME>  ReflectiveLoader function name in ReflectiveDLL.dll [default: yolo]
  -h, --help               Print help
  -V, --version            Print version
```

## 介绍

注入器使用传入的url参数下载反射DLL到内存中，并找到指定的反射函数名称，获得RAW。在目标进程中写入反射dll，并创建反射函数进行反射DLL的自加载。

Rust的编译产物可以很好的防止被逆向分析，并且该注入器使用了NTDLL脱钩技术防止被EDR检测。

[反射DLL参考](https://github.com/ccoskrnl/ReflectiveDLl)