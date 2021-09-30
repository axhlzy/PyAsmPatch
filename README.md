# PyAsmPatch
 Use lief, keystone and capstone to manually inline hook elf(so) files

```
[*] mergeSection => .inject => 0x38e0000
[*] GLOBAL_TABLE ---> 0x38e16e8
[*] STR_TABLE ---> 0x38e187c
[*] trampolines ---> 0x38e1554
[*] textCodes ---> 0x38e13c0
[*] SettingsMenuIn ---> 0x5475d8
    Current Needed Libraries : 
[*] liblog.so
[*] libstdc++.so
[*] libm.so
[*] libdl.so
[*] libc.so
[*] Create string at 0x38e1878	this is a test string!
[*] Create string at 0x38e188f	测试文本文件
[*] Create string at 0x38e18a2	ZZZ
[*] Create string at 0x38e18a6	called this function
```