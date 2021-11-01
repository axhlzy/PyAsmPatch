from AndroidPatch import AndroidPatcher
from Config import *


class UnityPatcher(AndroidPatcher):

    def __init__(self, filePath, ARCH=ARCH_ARM):
        AndroidPatcher.__init__(self, filePath, ARCH=ARCH)
        # gotMap add Got Functions
        for item in functionsMap.items():
            self.addGOT(int(item[1]), item[0])

    def hookInit(self, log=True):
        self.fixGot(log=log)
        self.fixU16ToU8()
        self.getSymbolByName("replaceStrInner")

    def fixGot(self, log):
        # 修改权限
        self.addHook(self.lf.get_symbol("il2cpp_init").value, jmpType="B", printTips=False, printRegs=False)
        self.mprotect(mPtr=functionsMap.get("GLOBAL_TABLE"), size=configSize["mProtect_size"], log=log)
        self.loadBaseToReg(reg="R9", log=True)
        self.relocationGot(reg="R9")
        self.endHook()

    def getSymbolByName(self, name, mPtr=None):
        tmpRet = super(UnityPatcher, self).getSymbolByName(name, mPtr)
        if tmpRet is not None:
            return tmpRet
        # 字符替换函数 (这个函数是在init的时候提前创建且仅创建一遍，不能在andHook内部去创建)
        if functionsMap.get(str(name)) is None and name == "replaceStrInner":
            tmpPC = self.currentPC
            tmpCode = self.currentCodes
            self.resetPC(self.currentCodes)
            self.recordSymbol("replaceStrInner", self.currentPC)
            self.saveEnv(simple=True)
            # R5 ShowLOG | R6 CmpResult |R7 pointer | R8 srcU8 | R9 cmpStart | R10 cmpEnd
            self.patchASM("MOV R5,R3")
            self.patchASM("MOV R7,R1")
            self.patchASM("MOV R8,R0")
            self.patchASM("MOV R9,R1")
            self.patchASM("MOV R10,R2")

            self.patchASM("CMP R5,#0x2")
            self.preAsm("BNE #loopStart")
            self.patchASM("MOV R3,R8")
            self.android_log_print_reg(formart="[*] SRC ---> %s")
            self.preAsm("B #loopOver")

            # if R6 + offset != R10
            self.patchASM("CMP R7,R10", labName="loopStart")
            # 跳转到 循环完成依旧没有匹配
            self.preAsm("BEQ #loopOver")
            self.strcmp(fromSR1="R7", fromSR2="R8", toReg="R6")
            self.strlen(fromSR="R7", toReg="R0")
            self.patchASM("ADD R7,R7,#1")
            self.patchASM("ADD R7,R7,R0")
            # 判断字符串相等，跳转到使用R7构造u16并返回
            self.patchASM("CMP R6,#0")
            self.preAsm("BEQ #foundEq")
            self.strlen(fromSR="R7", toReg="R0")
            self.patchASM("ADD R7,R7,#1")
            self.patchASM("ADD R7,R7,R0")
            # 跳转到下次循环
            self.preAsm("B #loopStart")

            # 使用R7构造u16并返回
            self.patchASM("CMP R5,#0x1", labName="foundEq")
            self.preAsm("BNE #jmpOver")
            self.prepareStack(1)
            self.patchASM("MOV R3,R8")
            self.saveRegToStack(reg="R7", index=0)
            self.android_log_print_reg(formart="[*] replace : %s ---> %s")
            self.patchASM("MOV R0,R7")
            self.restoreStack()
            # 跳转到最后返回的位置
            self.preAsm("B #jmpOver")

            # 循环完成依旧没有匹配
            self.patchASM("MOV R0,R8", labName="loopOver")

            # 最后返回的位置
            self.preLabel("jmpOver")
            self.jumpTo(functionsMap.get("il2cpp_string_new"), jmpType="REG", resetPC=False)
            self.preAsmEnable()
            self.restoreEnv(simple=True)
            self.currentCodes = self.currentPC
            self.resetPC(tmpPC)
            return tmpCode

    # fix unicode_to_utf8
    def fixU16ToU8(self, jmpType="B"):
        tmpPC = self.currentPC
        tmpFixBase = self.getSymbolByName("unicode_to_utf8")
        if jmpType == "LDR":
            self.saveCode(fromPtr=tmpFixBase + 0x28, codeIndex=3, insLength=2)
            self.jumpTo(toAddress=self.currentTramp, fromAddress=tmpFixBase + 0x24, jmpType=jmpType)
            self.jumpTo(self.getRelocation("calloc"), jmpType="REL", reg="R12", resetPC=False)
            self.restoreCode(codeIndex=3, needFix=False)
            self.jumpTo(toAddress=tmpFixBase + 0x30, resetPC=False, jmpType="LDR")
        elif jmpType == "B":
            self.jumpTo(toAddress=self.currentTramp, fromAddress=tmpFixBase + 0x24, jmpType=jmpType)
            self.jumpTo(self.getRelocation("calloc"), jmpType="REL", reg="R12", resetPC=False)
            self.jumpTo(toAddress=tmpFixBase + 0x28, resetPC=False, jmpType=jmpType)
        self.currentTramp = self.currentPC
        self.currentPC = tmpPC

    def getJValueArray(self, *args):
        # 四字节对齐
        tmpCPC = self.currentPC
        self.currentStr += (4 - self.currentStr % 4)
        self.resetPC(self.currentStr)
        tmpRetPtr = self.currentStr
        self.getPtr(tmpRetPtr)
        tmpList = [0x12, 0x34, 0x56, 0x78,
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,
                   eval(hex(len(args))), 0x00, 0x00, 0x00]
        for index in range(0, len(args)):
            # struct jValue[]
            # ptr.add(0xC)  ===>    arrayLength
            # ptr.add(0x10) ===>    第一个参数
            # ptr.add(0x18) ===>    第二个参数 (每个参数之前差8字节,前四字节为值 [后四个字节可能为TYPE(后四字节猜的)])
            if type(args[index]) is int:
                tmpList.extend(self.calOffsetToList(0, args[index], 0))
                tmpList.extend([0x00, 0x00, 0x00, 0x00])
            elif type(args[index]) is str:
                # 这里是有问题的,这里填写的str是静态的的地址,即使运行时候修复了也会崩,猜测可能会用到后四字节
                tmpList.extend(self.calOffsetToList(0, self.getStr(args[index]), 4))
                tmpList.extend([0x00, 0x00, 0x00, 0x00])
            elif type(args[index]) is bool:
                tmpList.extend([0x1 if args[index] else 0x0, 0x00, 0x00, 0x00])
                tmpList.extend([0x00, 0x00, 0x00, 0x00])
        tmpList.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # 0填充
        self.patchList(tmpList)
        self.currentStr = self.currentStr + len(tmpList)
        print("[*] Create JValueArray {} ---> {}".format(hex(tmpRetPtr), tmpList))
        self.currentPC = tmpCPC
        return tmpRetPtr

    def FindClass(self, clsName):
        self.getU16(clsName)
        self.jumpTo(functionsMap.get("FindClass"), jmpType="BL", resetPC=False)
        self.patchASM("MOV R4,R0")

    def GetStaticMethodID(self, funcName, sign):
        self.getU16(funcName)
        self.patchASM("MOV R5,R0")
        self.getU16(sign)
        self.patchASM("MOV R6,R0")
        self.patchASM("MOV R0,R4")
        self.patchASM("MOV R1,R5")
        self.patchASM("MOV R2,R6")
        self.jumpTo(functionsMap.get("GetStaticMethodID"), jmpType="BL", resetPC=False)
        self.patchASM("MOV R5,R0")

    def CallStaticVoidMethod(self, clsName, funcName, sign, *args):
        self.FindClass(clsName)
        self.GetStaticMethodID(funcName, sign)
        self.patchASM("MOV R0,R4")
        self.patchASM("MOV R1,R5")
        # args operation
        if len(args) != 0:
            self.loadToReg(self.getJValueArray(*args), toReg="R2")
        else:
            # 不是用到args时一定得将R2写成0，不然R2之前可能有不可预期的值，进入Call之后对jValue解析就会崩溃
            self.patchASM("MOV R2,#0")
        self.jumpTo(functionsMap.get("CallStaticVoidMethod"), jmpType="BL", resetPC=False)

    def getU16(self, mStr, reg="R0"):
        self.loadToReg(self.getStr(mStr), reg)
        self.jumpTo(functionsMap.get("il2cpp_string_new"), jmpType="BL", resetPC=False)
        if reg != "R0":
            self.patchASM("MOV {},R0".format(reg))

    # Use R0 - R4 /  use fromReg > R4
    def convertToU8(self, toReg="R0", fromReg="R0"):
        # 固定一个位置存放未初始化变量
        self.loadToReg(self.getPtr(0xFFFFFFF0), toReg="R2")
        self.patchASM("MOV R4,R2")
        # 拿到 U16长度
        self.patchASM("LDR {},[{},#0x8]".format("R3", fromReg))
        # 长度乘以二
        self.patchASM("ADD R1,{},{}".format("R3", "R3"))
        # u16开始位置
        self.patchASM("ADD R0,{},#0xC".format(fromReg))
        self.jumpTo(self.getSymbolByName("unicode_to_utf8"), jmpType="BL", reg="R3", resetPC=False)
        self.patchASM("LDR {},[R4]".format(toReg))
        # 把这个指针放在 R2
        self.patchASM("MOV R1,R4")

    # 用来进行汉化，记录一个 key-value
    def recordStringMap(self, tmpMap):
        tmpStrStart = self.currentStr
        for item in tmpMap.items():
            stringMap.setdefault(item[0], item[1])
            self.getStr(item[0], useCache=False)
            self.getStr(item[1], useCache=False)
        tmpStrEnd = self.currentStr
        return tmpStrStart, tmpStrEnd

    # retStr:存放字典映射关系
    # fromReg:我们需要处理的字符串放在哪里(传入u8)
    # toReg:处理后的字符串放在那里(传出u8/u16)
    # use R0 - R3
    def getReplaceStr(self, argReg="R0", retReg="R0", Obj=None):
        self.convertToU8(fromReg=argReg, toReg="R0")
        if type(Obj) is dict:
            # 返回替换值 并打出日志
            ret = self.recordStringMap(Obj)
            self.loadToReg(ret[0], toReg="R1")
            self.loadToReg(ret[1], toReg="R2")
            self.patchASM("MOV R3,#{}".format(1))
        else:
            # 只显示原字符串并
            self.patchASM("MOV R3,#{}".format(2))
        # 返回了一个字符串 起始位置 和 结束位置
        self.jumpTo(self.getSymbolByName("replaceStrInner"), jmpType="BL", resetPC=False)
        if retReg != "R0":
            self.patchASM("MOV {},R0".format(retReg))
