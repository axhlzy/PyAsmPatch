from Hook import MergeUtils, UnityJumper

if __name__ == '__main__':
    ins = MergeUtils(r"C:\xxxxxxx\libil2cpp_cp32.so")
    newSoPath = ins.mergeSection(".inject")

    # 如果要用到JNI 这些函数是必填项
    ins.recordSymbols({"il2cpp_string_new": 0x2BE988, "FindClass": 0xEE5684, "GetStaticMethodID": 0xEE60EC,
                       "CallStaticVoidMethod": 0xEE74E4})

    # 自己需要的Hook的函数名以及地址（记得recordSymbol在UnityJumper构造之前添加）
    ins.recordSymbol("ShowSettings", 0xB69D4C)
    ins.recordSymbol("UI_Splash", 0x41c4c8)

    ins = UnityJumper(newSoPath)

    ins.addHook(ins.getSymbolByName("UI_Splash"), printRegs=False)
    ins.android_log_print_msg(msg="描述 : called this function")
    # android_log_print_reg 从R3开始,多余的参数使用堆栈传参 prepareStack saveRegToStack restoreStack
    # 以下为一个简单的demo 几句话即可完成 log 带堆栈传参的调用    
    ins.loadToReg(ins.addPtr(ins.getSymbolByName("UI_Splash")), reg="R3")
    ins.patchASM("LDR R3,[R3]")
    ins.loadToReg(ins.getStr("UI_Splash"), reg="R4")
    ins.prepareStack(1)
    ins.saveRegToStack(reg="R4", index=0)
    ins.android_log_print_reg(formart="called from %p (%s)")
    ins.restoreStack(1)
    ins.CallStaticVoidMethod("com/ironsource/unity/androidbridge/AndroidBridge", "onResume", "()V", 0)
    ins.endHook()

    ins.save("libil2cpp_final.so")
