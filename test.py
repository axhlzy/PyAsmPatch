from Hook import functionsMap, MergeUtils, UnityJumper

if __name__ == '__main__':
    ins = MergeUtils(r"C:\Users\pc\Desktop\temp\26_com.xxxxxx\libil2cpp_cp32.so",
                     r"C:\Users\xxxxxxxx\libinject.so")
    newSoPath = ins.mergeSection(".inject")

    ins.recordSymbols({"il2cpp_string_new": 0x1BD130, "FindClass": 0xAEA06C, "GetStaticMethodID": 0xAEA9D4,
                       "CallStaticVoidMethod": 0xAEBDB8})

    ins.recordSymbol("ShowSettings", 0xB69D4C)

    ins = UnityJumper(newSoPath)

    ins.addHook(functionsMap.get("ShowSettings"), jmpType="B")
    ins.android_log_print(msg="中文描述 : called this function")
    ins.CallStaticVoidMethod("com/ironsource/unity/androidbridge/AndroidBridge", "onResume", "()V", 0)
    ins.endHook()

    ins.save("libil2cpp_final.so")
