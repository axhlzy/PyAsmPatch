# PyAsmPatch
Use lief, keystone and capstone to manually inline hook elf(libil2cpp.so) files

 详见：
 https://www.jianshu.com/p/915a512fd7e9
 
```
[*] mergeSection => .inject => 0x1e8c000

[*] recordSym ---> GLOBAL_TABLE   	0x1e8d6e8
[*] recordSym ---> STR_TABLE      	0x1e8d87c
[*] recordSym ---> trampolines    	0x1e8d554
[*] recordSym ---> textCodes      	0x1e8d3c0
[*] recordSym ---> il2cpp_string_new        	0x1bd130   ---> 0x1be130
[*] recordSym ---> FindClass                	0xaea06c   ---> 0xaeb06c
[*] recordSym ---> GetStaticMethodID        	0xaea9d4   ---> 0xaeb9d4
[*] recordSym ---> CallStaticVoidMethod     	0xaebdb8   ---> 0xaecdb8
[*] recordSym ---> ShowSettings             	0xb69d4c   ---> 0xb6ad4c
[*] Create string at 0x1e8d878	ZZZ
[*] Create string at 0x1e8d87c	中文描述 : called this function
[*] Create string at 0x1e8d8a0	com/ironsource/unity/androidbridge/AndroidBridge
[*] Create string at 0x1e8d8b4	onResume
[*] Create string at 0x1e8d8c1	()V

Process finished with exit code 0

```
