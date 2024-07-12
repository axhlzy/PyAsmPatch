# PyAsmPatch
Use lief, keystone and capstone to manually inline hook elf(libil2cpp.so) file

 # 当前已完成功能
 1. 合并编译出的so中的指定节到我们待修改的so（MergeUtils中提供的 recordSymbols 屏蔽掉合并后函数地址的变化）
 2. UnityJumper.addHook 后当前pc已经准在了待写代码的位置，写完代码调用 UnityJumper.endHook() 
 3. addHook中也支持查看hook位置的Regs值(printRegs=True),具体实现是读取进入hook代码前对所有用户态寄存器保存在堆栈的值(R11/FP)
 4. Hook InitArray 的第一个函数（Unity是hook il2cpp_init），在此处获取基址，并将GOT_TABLE中的每一项加上这个基址重新写回，0标识结束
 5. LDR 指令修复,其他PC相关指令后续再说  TODO .....
 6. 封装一些常用的函数 android_log_print mprotect callFunction Unity.JNI(单个参数没问题，多参数有bug)
 
 ## TIPS:
 1. ins.addGOT() 和 ins.addPtr() : 
     - addGOT 添加到 GOT_TABLE 启动时候会加基地址，用作blx Rx
     - addPtr 添加到 GLOBAL_TABLE ，仅用作存储，但是在 recordSymbol中也会用到addPtr,此处的调用会调用 addGOT
 2. ins.addBP() 添加一个死循环，IDA调式BUG的时候使用 (或者ins.resetPC(0x12345678) 后使用)
     
 详见：
 https://bbs.pediy.com/thread-269601.htm
 
 
```
C:\ProgramData\Anaconda3\envs\APKUtils\python.exe C:\Users\pc\PycharmProjects\SoInject\scripts\射击之王_com_gzcc_zttnl_sjzw.py
[*] mergeSection => .inject => 0x1e8c000

[*] recordSym ---> GLOBAL_TABLE   	0x1e8dd28
[*] recordSym ---> STR_TABLE      	0x1e8e1dc
[*] recordSym ---> GOT_TABLE      	0x1e8e690
[*] recordSym ---> trampolines    	0x1e8d874
[*] recordSym ---> textCodes      	0x1e8d3c0


[*] recordSym ---> il2cpp_string_new        	0x1bd130   ---> 0x1be130
[*] recordSym ---> FindClass                	0xaea06c   ---> 0xaeb06c
[*] recordSym ---> GetStaticMethodID        	0xaea9d4   ---> 0xaeb9d4
[*] recordSym ---> CallStaticVoidMethod     	0xaebdb8   ---> 0xaecdb8
[*] recordSym ---> ShowSettings             	0xb69d4c   ---> 0xb6ad4c
[*] recordSym ---> ShowSettings1            	0xb69db4   ---> 0xb6adb4
[*] recordSym ---> readArgsReg    	0x1e8d3c0
[*] Create string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e1dc	
Break at 0x0 Registers ---> 
R0~R3:	%p %p %p %p 
R4~R10:	%p %p %p %p %p %p %p 
FP:%p IP:%p LR:%p SP:%p CPSR:%p
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e24c	mprotect ret = %d  args : %p %p %p
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e26f	soAddr -> %p
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e27c	GOT relocation %p ---> %p ---> %p
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e29e	Finished GOT relocation all:%d
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e2bd called this function
[*] Get string at 0x1e8e1d8	ZZZ
[*] Create string at 0x1e8e2e1	Text CAllED

```


后续可能的用法：

可以考虑用这种方式 直接静态遍历text段 找出所有的 svc 并 hook 代理掉
```
LOAD:0000000000534D00 C8 07 80 D2                 MOV             X8, #0x3E ; '>'
LOAD:0000000000534D04 01 00 00 D4                 SVC             0
LOAD:0000000000534D08 1F 04 40 B1                 CMN             X0, #1,LSL#12
LOAD:0000000000534D0C 00 94 80 DA                 CINV            X0, X0, HI
LOAD:0000000000534D10 88 EC 00 54                 B.HI            loc_536AA0
LOAD:0000000000534D14 C0 03 5F D6                 RET
```

