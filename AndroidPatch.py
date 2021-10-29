from AsmPatch import AsmPatcher
from Config import ARCH_ARM, functionsMap, configSize


class AndroidPatcher(AsmPatcher):
    def __init__(self, filePath, ARCH=ARCH_ARM):
        AsmPatcher.__init__(self, filePath, ARCH=ARCH_ARM)
        print("--------------------------------------------------------------------------")
        self.hookInit()

    def hookInit(self, log=True):
        self.fixGot(log=log)

    def getSymbolByName(self, name, mPtr=None):
        tmpRet = super(AndroidPatcher, self).getSymbolByName(name, mPtr)
        if tmpRet is not None:
            return tmpRet

    def fixGot(self, log):
        if self.lf.ctor_functions[0] is None:
            raise Exception("There is no ctor_functions")
        # 修改权限
        self.addHook(self.lf.ctor_functions[0].value, jmpType="B", printTips=False, printRegs=False)
        # 这个size其实可以填的很大，即使返回了-1，但是它是按照页来修改访问属性的，问题不大，所以返回-1表示我们已经覆盖了全部（超出了）
        self.mprotect(mPtr=functionsMap.get("GLOBAL_TABLE"), size=configSize["mProtect_size"], log=log)
        self.loadBaseToReg(reg="R9", log=True)
        self.relocationGot(reg="R9")
        self.endHook()

    # 获取 il2cpp base address
    # 代码执行到这里的时候我们知道当前的pc值以及当前代码静态的地址，所以我们相减即可得到当前的so基地址
    def loadBaseToReg(self, reg="R4", log=False):
        self.loadToReg(self.getPtr(self.currentPC + 7 * self._pSize), toReg="R1")
        self.patchASM("LDR R2,[R1]")
        self.patchASM("SUB R0,PC,R2")
        self.patchASM("MOV {},R0".format(reg))
        if log:
            self.patchASM("MOV R3,R0")
            self.android_log_print_reg(formart="soAddr -> %p")

    # while(GOT_TABLE[index]!=0x0){
    #       GOT_TABLE[index] += soAddr
    # }
    def relocationGot(self, reg="R9"):
        self.prepareStack(2)
        self.loadToReg(functionsMap.get("GOT_TABLE"), toReg="R5")
        self.patchASM("MOV R7,#0")
        self.patchASM("MOV R10,#0")
        # R5:存放指针 R6:存放具体值 R7:存放偏移 R8:CurrentPtr
        self.patchASM("ADD R8,R5,R7")
        self.patchASM("LDR R6,[R8]")
        self.patchASM("CMP R6,#0")
        # 标识结束，直接跳转到 endHook
        self.jumpTo(self.currentPC + self._pSize * 24, jmpType="BEQ", resetPC=False)
        self.patchASM("MOV R3,R8")
        self.patchASM("ADD R10,#1")
        self.saveRegToStack(reg="R6", index=0)
        self.patchASM("ADD R6,R6,{}".format(reg))
        self.saveRegToStack(reg="R6", index=1)
        self.android_log_print_reg(formart="GOT relocation %p ---> %p ---> %p")
        self.patchASM("STR R6,[R8]")
        self.patchASM("ADD R7,R7,#4")
        self.jumpTo(self.currentPC - self._pSize * 26, jmpType="B", resetPC=False)
        self.patchASM("MOV R3,R10")
        self.android_log_print_reg(formart="Finished GOT relocation all:%d")
        self.restoreStack(2)

    # 修改PC附近RWX
    def mprotect(self, mPtr=None, size=4096, prot=7, log=False):
        if mPtr is None:
            self.patchASM("MOV R2,PC")
        else:
            self.loadToReg(self.getPtr(mPtr), toReg="R2")
        self.prepareStack(3)
        self.patchASM("MOV R1,R2,LSR#12")
        self.patchASM("MOV R0,R1,LSL#12")
        self.saveRegToStack(reg="R0", index=0)
        self.patchASM("MOV R1,#{}".format(size))
        self.saveRegToStack(reg="R1", index=1)
        self.patchASM("MOV R2,#{}".format(prot))
        self.saveRegToStack(reg="R2", index=2)
        self.jumpTo(self.getRelocation("mprotect"), jmpType="REL", reg="R3", resetPC=False)
        self.patchASM("MOV R3,R0")
        if log:
            self.android_log_print_reg(formart="mprotect ret = %d  args : %p %p %p")
        self.restoreStack(3)

    def strcmp(self, fromSR1, fromSR2, toReg="R0"):
        if str(fromSR1).startswith("R"):
            if str(fromSR1) != "R0":
                self.patchASM("MOV {},{}".format("R0", fromSR1))
        elif type(fromSR1) is str:
            # 填写一个具体的字符串的情况
            self.loadToReg(self.getStr(fromSR1), toReg="R0")
        if str(fromSR2).startswith("R"):
            if str(fromSR2) != "R1":
                self.patchASM("MOV {},{}".format("R1", fromSR2))
        elif type(fromSR2) is str:
            self.loadToReg(self.getStr(fromSR2), toReg="R1")
        self.jumpTo(self.getRelocation("strcmp"), jmpType="REL", reg="R2", resetPC=False)
        if toReg != "R0":
            self.patchASM("MOV {},R0".format(toReg))

    def strcat(self, str0, str1, toReg="R0"):
        if str(str0).startswith("R") and str(str0) != "R0":
            self.patchASM("MOV {},{}".format("R0", str0))
        elif type(str0) is str:
            self.loadToReg(self.getStr(str0), toReg="R0")
        if str(str1).startswith("R") and str(str0) != "R1":
            self.patchASM("MOV {},{}".format("R1", str0))
        elif type(str1) is str:
            self.loadToReg(self.getStr(str1), toReg="R1")
        self.jumpTo(self.getRelocation("strcat"), jmpType="REL", reg="R3", resetPC=False)
        if toReg != "R0":
            self.patchASM("MOV {},R0".format(toReg))

    def strlen(self, fromSR="R0", toReg="R0"):
        if str(fromSR).startswith("R"):
            if str(fromSR) != "R0":
                self.patchASM("MOV {},{}".format("R0", fromSR))
        elif type(fromSR) is str:
            self.loadToReg(self.getStr(fromSR), toReg="R0")
        self.jumpTo(self.getRelocation("strlen"), jmpType="REL", reg="R2", resetPC=False)
        if toReg != "R0":
            self.patchASM("MOV {},R0".format(toReg))

    def calloc(self, count, size, toReg="R0"):
        self.patchASM("MOV R0,#{}".format(count))
        self.patchASM("MOV R1,#{}".format(size))
        self.jumpTo(self.getRelocation("calloc"), jmpType="REL", reg="R12", resetPC=False)
        if toReg != "R0":
            self.patchASM("MOV {},R0".format(toReg))

    def malloc(self, size, toReg="R0"):
        self.patchASM("MOV R0,#{}".format(size))
        self.jumpTo(self.getRelocation("malloc"), jmpType="REL", reg="R12", resetPC=False)
        if toReg != "R0":
            self.patchASM("MOV {},R0".format(toReg))

    def free(self, fromReg="R1"):
        self.patchASM("MOV R0,{}".format(fromReg))
        self.jumpTo(self.getRelocation("free"), jmpType="REL", reg="R12", resetPC=False)

    def android_log_print_msg(self, prio=3, tag="ZZZ", msg="Called"):
        self.patchASM("MOV R0, #{}".format(prio))
        self.loadToReg(self.getStr(tag), toReg="R1")
        self.loadToReg(self.getStr(msg), toReg="R2")
        self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R3", resetPC=False)

    # 依次对R3,sp,sp#4,sp#8... 进行参数传递
    def android_log_print_reg(self, prio=3, tag="ZZZ", formart="---> %p"):
        self.patchASM("MOV R0, #{}".format(prio))
        self.loadToReg(self.getStr(tag), toReg="R1")
        self.loadToReg(self.getStr(formart), toReg="R2")
        self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)

    def callFunction(self, mPtr, *args):
        for i in range(0, len(args)):
            if i <= 3:
                if type(args[i]) == str:
                    self.loadToReg(self.getStr(args[i]), "R{}".format(i - 1))
                elif type(args[i]) == int:
                    self.patchASM("MOV R{},{}".format("R{}".format(i - 1), args[i]))
            else:
                argL = len(args) - 4
                self.prepareStack(argL)
                for t in range(argL, len(args)):
                    self.loadToReg(mPtr=self.getPtr(mPtr), toReg="R4")
                    self.saveRegToStack(reg="R4", index=t - 4)
                self.restoreStack()
        self.jumpTo(mPtr, jmpType="BL", resetPC=False, reg="R4")
