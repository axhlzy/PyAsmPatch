import os

from MergeUtils import MergeUtils
from UnityPatch import UnityPatcher

if __name__ == '__main__':
    ins = MergeUtils(os.getcwd()+"/libil2cpp_cp32.so")
    newSoPath = ins.mergeSection(".inject")

    ins.recordSymbols({"FindClass": 0xA0CB0C, "GetStaticMethodID": 0xA0DAE4, "CallStaticVoidMethod": 0xA0F360})

    ins.recordSymbol("Sub", 0x9EFD38)
    ins.recordSymbol("OnPopulateMesh+140", 0x9EE45C)

    ins = UnityPatcher(newSoPath)
    repStr = ({"惊吓彩蛋": "惊喜彩蛋", "contact@gameresort.com": "axhlzy@live.cn", "版本 2.12": " ", "有问题或评论吗？": " "})

    ins.addHook(ins.getSymbolByName("OnPopulateMesh+140"), printRegs=False, printTips=False)
    ins.getArg(0, toReg="R5")
    ins.getReplaceStr(repDic=repStr, argReg="R5", retReg="R0", LogType=1)
    ins.setArg(0, fromReg="R0")
    ins.endHook()

    # ins.addHook(ins.getSymbolByName("Sub"), printRegs=False)
    # ins.android_log_print_msg(msg="描述 : called this function")
    # # android_log_print_reg 从R3开始,多余的参数使用堆栈传参 prepareStack saveRegToStack restoreStack
    # # 以下为一个简单的demo 几句话即可完成 log 带堆栈传参的调用
    # ins.loadToReg(ins.getPtr(ins.getSymbolByName("Sub")), toReg="R3")
    # ins.patchASM("LDR R3,[R3]")
    # ins.loadToReg(ins.getStr("Sub"), toReg="R4")
    # ins.prepareStack(1)
    # ins.saveRegToStack(reg="R4", index=0)
    # ins.android_log_print_reg(formart="called from %p (%s)")
    # ins.restoreStack(1)
    # ins.CallStaticVoidMethod("com/ironsource/unity/androidbridge/AndroidBridge", "onResume", "()V", 0)
    # ins.endHook()

    ins.save("libil2cpp_final.so")
