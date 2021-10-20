from AndroidPatch import CommonBase
from Config import functionsMap, ARCH_ARM


class UnityJumper(CommonBase):

    def __init__(self, filePath, ARCH=ARCH_ARM):
        CommonBase.__init__(self, filePath, ARCH=ARCH)
        # gotMap add Got Functions
        for item in functionsMap.items():
            self.addGOT(int(item[1]), item[0])

    def hookInit(self, log=True):
        self.addHook(self.lf.get_symbol("il2cpp_init").value, jmpType="B", printTips=False, printRegs=False)
        self.fixGot(log=log)

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

    def getUnityStr(self, mStr, reg="R0"):
        self.loadToReg(self.getStr(mStr), reg)
        self.jumpTo(functionsMap.get("il2cpp_string_new"), jmpType="BL", resetPC=False)
        if reg != "R0":
            self.patchASM("MOV {},R0".format(reg))

    def FindClass(self, clsName):
        self.getUnityStr(clsName)
        self.jumpTo(functionsMap.get("FindClass"), jmpType="BL", resetPC=False)
        self.patchASM("MOV R4,R0")

    def GetStaticMethodID(self, funcName, sign):
        self.getUnityStr(funcName)
        self.patchASM("MOV R5,R0")
        self.getUnityStr(sign)
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
            self.loadToReg(self.getJValueArray(*args), reg="R2")
        else:
            # 不是用到args时一定得将R2写成0，不然R2之前可能有不可预期的值，进入Call之后对jValue解析就会崩溃
            self.patchASM("MOV R2,#0")
        self.jumpTo(functionsMap.get("CallStaticVoidMethod"), jmpType="BL", resetPC=False)

    def setFunctionRet(self, pFunction, pRet):
        self.resetPC(pFunction)
        self.patchASM("MOV R0, #{}".format(pRet))
        self.nop(self.currentPC)

    def nop(self, pFunction):
        self.resetPC(pFunction)
        self.patchASM("BX LR")
