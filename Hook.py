#
#  @Author      lzy <axhlzy@live.cn>
#  @HomePage    https://github.com/axhlzy
#  @CreatedTime 2021/09/30 18:42
#  @UpdateTime  2021/10/19 15:35
#  @Des         Use lief, keystone and capstone to manually inline hook elf(libil2cpp.so) file
#

import os
import logging
import sys

import lief
import keystone
import capstone

ARCH_ARM = 4
ARCH_ARM64 = 8
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

configSize = {"GLOBAL_TABLE": 2000, "STR_TABLE": 2000, "GOT_TABLE": 2000, "trampolines": 2000, "textCodes": 2000,
              "GOT_TABLE_fill": 500, "mProtect_size": 1024 * 40}
hookedFunctions = {}
functionsMap = {}
gotMap = {}


class JumperBase:

    def __init__(self, filePath, ARCH=ARCH_ARM):

        self.filePath = filePath
        self.fileName = os.path.basename(filePath)
        self.fileDIR = os.path.abspath(filePath)
        self.lf = lief.parse(filePath)

        self.currentPC = 0
        self.currentPtr = functionsMap.get("GLOBAL_TABLE")
        self.currentStr = functionsMap.get("STR_TABLE")
        self.currentGOT = functionsMap.get("GOT_TABLE")
        self.currentTramp = functionsMap.get("trampolines")
        self.currentCodes = functionsMap.get("textCodes")

        self.mapPtr = {}
        self.mapStr = {}

        self._pSize = ARCH
        self._fixLdrPC = {}
        self._AllocSpSize = 0
        self._lastPC = 0
        self._jumpBackPC = 0
        self._returnAddr = 0
        self._codeContainer = [[], [], [], [], [], [], [], [], []]
        self._recordFromToLOG = []

        if ARCH == ARCH_ARM:
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        elif ARCH == ARCH_ARM64:
            # self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            # self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_ARM)
            raise Exception("Todo by yourself -.-")
        else:
            raise Exception("Todo by yourself -.-")

        # 我们需要使用到的导出函数（主要是一些系统函数，如果有没有，我们需要自己去添加需要的lib以及添加导出项）
        # print("\nCurrent Needed Libraries : ")
        # for name in self.lf.libraries:
        #     print("\t[*] " + name)
        # if not self.Jumper.lf.has_library("liblog.so"):
        #     self.Jumper.lf.add_library("liblog.so")

    def resetPC(self, PC):
        self.currentPC = PC

    # 计算地址偏移
    def calOffset(self, fromAddr, toAddr, offset=2):
        if fromAddr == 0:
            return str(hex((toAddr & 0xFFFFFFFF)))
        else:
            return str(hex((toAddr - (fromAddr + self._pSize * offset) & 0xFFFFFFFF)))

    def calOffsetToList(self, fromAddr, toAddr=0, offset=2):
        tmpStr = str(self.calOffset(fromAddr, toAddr, offset)).lstrip('0x')
        while tmpStr.__len__() < 8:
            tmpStr = "0" + tmpStr
        tmpList = list(bytearray.fromhex(tmpStr))
        # arm32 小端存储
        if self._pSize == ARCH_ARM:
            tmpList.reverse()
        return tmpList

    def ldrGenerator(self, loadAddress, register):
        pass

    def getAsmFromList(self, mList, startAddr=0x1000):
        retList = []
        for i in self.cs.disasm(bytes(mList), startAddr):
            retList.append("{} {}".format(i.mnemonic, i.op_str))
        return retList

    def getAsmFromAddress(self, address=0, length=1):
        if address == 0:
            address = self.currentPC
        return self.getAsmFromList(self.lf.get_content_from_virtual_address(address, 4 * length), address)

    def patchList(self, mList):
        self.lf.patch_address(self.currentPC, mList)
        self.currentPC += mList.__len__()

    def patchASM(self, asm="nop"):
        self.patchList(self.ks.asm(asm)[0])

    def saveEnv(self, fpReg="R11"):
        self.patchASM("push {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")
        self.patchASM("MRS R11, CPSR")
        self.patchASM("MOV R12, SP")
        self.patchASM("STMFD SP!, {R11,R12}")
        self.patchASM("MOV {},SP".format(fpReg))

    def restoreEnv(self):
        self.patchASM("LDMFD SP!, {R11,R12}")
        self.patchASM("MSR CPSR, R11")
        self.patchASM("pop {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")

    def restoreCode(self, codeIndex=0, fromAddress=0):
        tmp = self._fixLdrPC.get("fixLdrPC_{}".format(fromAddress))
        if tmp is not None:
            tmpInsList = self.getAsmFromList(self._codeContainer[codeIndex])
            for index in range(0, len(tmpInsList)):
                item = tmpInsList[index]
                if item.find("ldr") != -1 and item.find("pc") != -1:
                    tmpReg = item[item.find("ldr ") + 4:item.find(", [")]
                    self.patchASM("LDR {}, [PC,#0]".format(tmpReg))
                    self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
                    self.patchList(self.calOffsetToList(self.currentPC - 4, tmp, 1))
                # 修复 BL
                elif item.find("BL") != -1:
                    # [31:28]位是条件码
                    # [27: 24]位为"1010"(0xeaffffff为一条指令的二进制机器码)时，表示B跳转指令
                    # [23: 0] 表示一个相对于PC的偏移地址
                    # todo
                    pass
                elif item.find("BLX") != -1:
                    # todo
                    pass
                elif item.find("B") != -1:
                    # todo
                    pass
                else:
                    self.patchASM(item)
        else:
            self.patchList(self._codeContainer[codeIndex])

    def save(self, name=None):
        if self.currentGOT > self.getSymbolByName("GOT_TABLE") + configSize["GOT_TABLE"] \
                or self.currentPtr > self.getSymbolByName("STR_TABLE") + configSize["STR_TABLE"] \
                or self.currentPtr > self.getSymbolByName("GLOBAL_TABLE") + configSize["GLOBAL_TABLE"] \
                or self.currentTramp > self.getSymbolByName("trampolines") + configSize["trampolines"]:
            raise Exception("Out of inject size")
        if self.currentCodes > self.getSymbolByName("textCodes") + configSize["textCodes"]:
            print("textCodes may be exceeded here")

        # 保存在传入so的目录下，未填写名称则默认在原名称后面添加一个N
        if name is None:
            oldNameSp = self.fileName.split(".")
            newName = oldNameSp[0] + "N." + oldNameSp[1]
            path = self.fileDIR.replace(self.fileName, newName)
        else:
            path = os.path.dirname(self.filePath) + "/" + name
        self.lf.write(path)
        return path

    @staticmethod
    def checkJmpRange(ptrFrom, ptrTo):
        # B指令和BL指令最大跳转距离是 ±32M (bits[23:0]是立即数空间,指令最低两位都为 0,去除一个符号位，即为2^25)
        if abs(ptrFrom - ptrTo) >= 32 * 1024 * 1024:
            raise Exception("Out of Jump range (|{} - {}| = {} > {})".format(hex(ptrFrom), hex(ptrTo),
                                                                             hex(abs(ptrFrom - ptrTo)),
                                                                             hex(32 * 1024 * 1024)))

    # codeIndex 保存被覆盖的几条指令
    # jmpType   跳转方式: b bl rel ldr
    # reg       ldr 跳转借用的寄存器(请选择没有使用到的寄存器)
    # reSetPC   是否把pc指向跳转过去的位置
    def jumpTo(self, toAddress=0, fromAddress=0, codeIndex=-1, jmpType="LDR", reg="R12", resetPC=True,
               resetBackPC=False, showLog=False):
        if fromAddress != 0:
            self.resetPC(fromAddress)
        else:
            fromAddress = self.currentPC

        if toAddress == 0:
            toAddress = self._returnAddr

        # 记录原本被替换的AsmCode
        def SaveCode():
            if jmpType == "B" or jmpType == "BL":
                # 记录函数返回地址
                if resetBackPC:
                    self._jumpBackPC = fromAddress + self._pSize * 1
                if codeIndex != -1:
                    self._codeContainer[codeIndex] = self.lf.get_content_from_virtual_address(self.currentPC,
                                                                                              self._pSize * 1)
            elif jmpType == "LDR":
                if resetBackPC:
                    self._jumpBackPC = fromAddress + self._pSize * 3
                if codeIndex != -1:
                    self._codeContainer[codeIndex] = self.lf.get_content_from_virtual_address(self.currentPC,
                                                                                              self._pSize * 3)
            # fix     ldr pc -> ldr r12  from self._fixLdrPC
            tmpInsList = self.getAsmFromList(self._codeContainer[codeIndex])
            # tmpCodeContainer = []
            for index in range(0, len(tmpInsList)):
                item = tmpInsList[index]
                if item.find("ldr") != -1 and item.find("pc") != -1:
                    # tmpCodeContainer.extend(self.ks.asm(tmpInsList[index].replace("pc", "r12"))[0])
                    tmpLdrPC = fromAddress + self._pSize * (index + 2) + eval(item[item.find("#") + 1:item.find("]")])
                    self._fixLdrPC.setdefault("fixLdrPC_{}".format(fromAddress), tmpLdrPC)
                else:
                    pass
                    # tmpCodeContainer.extend(self.ks.asm(tmpInsList[index])[0])
            # self._codeContainer[codeIndex] = tmpCodeContainer

        def JMP_B():
            self.checkJmpRange(self.currentPC, toAddress)
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 1
            self.patchASM("B #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))  # B/BL 本就是从当前位置算起
            if showLog:
                print('\n[*] Patch Code TYPE : JMP_B')
                tmpPC = self.currentPC - 4
                print("\t" + hex(tmpPC) + " " + self.getAsmFromList(self._codeContainer[codeIndex])[0]
                      + "\t--->\t" + self.getAsmFromAddress(tmpPC)[0])

        def JMP_BL():
            self.checkJmpRange(self.currentPC, toAddress)
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 1
            self.patchASM("BL #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))
            if showLog:
                print('\n[*] Patch Code TYPE : JMP_BL')
                tmpPC = self.currentPC - 4
                print("\t" + hex(tmpPC) + " " + self.getAsmFromList(self._codeContainer[codeIndex])[0]
                      + "\t--->\t" + self.getAsmFromAddress(tmpPC)[0])

        def JMP_BEQ():
            self.checkJmpRange(self.currentPC, toAddress)
            self.patchASM("BEQ #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))

        def JMP_BNE():
            self.checkJmpRange(self.currentPC, toAddress)
            self.patchASM("BNE #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))

        def JMP_LDA():
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 3
            self.patchASM("LDR {},[PC]".format(reg))
            self.patchASM("ADD PC,{}".format(reg))
            self.patchList(self.calOffsetToList(self.currentPC - 4, toAddress))  # 起点算的是pc的位置(上一条)，而不是当前位置

            if showLog:
                print('\n[*] Patch Code TYPE : JMP_LDA')
                tmpPC = self.currentPC - 4 * 3
                listPatch = self.lf.get_content_from_virtual_address(tmpPC + 4 * 2, 4)
                listPatchCP = listPatch.copy()
                listPatchCP.reverse()
                listStr = ""
                for i in listPatchCP:
                    listStr += hex(i)
                listStr = "0x" + listStr.replace("0x", "").lstrip("0")

                tmpSrcCode = self.getAsmFromList(self._codeContainer[codeIndex])
                print("\t" + hex(tmpPC + 4 * 0) + " " + tmpSrcCode[0]
                      + "\t\t\t\t    \t" + self.getAsmFromAddress(tmpPC + 4 * 0)[0])
                print("\t" + hex(tmpPC + 4 * 1) + " " + tmpSrcCode[1]
                      + "\t\t\t\t--->\t" + self.getAsmFromAddress(tmpPC + 4 * 1)[0])
                print("\t" + hex(tmpPC + 4 * 2) + " " + tmpSrcCode[2]
                      + "\t\t\t    \t" + str(listPatch) + "  " + listStr)

        def JMP_REG():
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 5
            self.patchASM("LDR {},[PC,#4]".format(reg))
            self.patchASM("ADD {},PC,{}".format(reg, reg))
            self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
            self.patchList(self.calOffsetToList(self.currentPC - 8, toAddress))
            self.patchASM("BLX {}".format(reg))

        def JMP_REL():
            self.patchASM("LDR {}, [PC,#0xC]".format(reg))
            self.patchASM("ADD {}, PC, {}".format(reg, reg))
            self.patchASM("LDR {}, [{}]".format(reg, reg))
            self.patchASM("BLX {}".format(reg))
            self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
            self.patchList(self.calOffsetToList(self.currentPC - 8, toAddress, 0))

        switch = {'LDR': JMP_LDA,  # 远距离的B
                  'REG': JMP_REG,  # 远距离的BL
                  'REL': JMP_REL,  # 跳转GOT
                  'BEQ': JMP_BEQ,
                  'BNE': JMP_BNE,
                  'BL': JMP_BL,
                  'B': JMP_B}
        switch.get(jmpType, JMP_B)()
        if resetPC:
            self.currentPC = toAddress

    def loadToReg(self, mPtr, reg="R0", fix=1):
        self.patchASM("LDR {}, [PC,#4]".format(reg))
        self.patchASM("ADD {}, PC, {}".format(reg, reg))
        self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
        self.patchList(self.calOffsetToList(self.currentPC - 4, mPtr, fix))

    def saveRegToMem(self, fromReg="R0", toPtr=0x0, tmpReg="R12"):
        self.patchASM("LDR {}, [PC,#8]".format(tmpReg))
        self.patchASM("ADD {}, PC, {}".format(tmpReg, tmpReg))
        self.patchASM("STR {}, [{}]".format(fromReg, tmpReg))
        self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
        self.patchList(self.calOffsetToList(self.currentPC - 4, toPtr, 0))

    def addGOT(self, mPtr, des=None):
        self._lastPC = self.currentPC
        self.resetPC(self.currentGOT)
        tmpAddr = self.currentGOT
        self.patchList(self.calOffsetToList(0, mPtr))
        self.currentGOT = self.currentPC
        self.currentPC = self._lastPC
        tmpKey = mPtr if des is None else des
        gotMap.setdefault(tmpKey, tmpAddr)
        return tmpAddr

    def getPtr(self, mPtr):
        for item in self.mapPtr.items():
            if item[1] == mPtr:
                return item[0]
        # 保存jumper中的_currentPC
        self._lastPC = self.currentPC
        # 修改jumper中的保存jumper中的_currentPC指向 GLOBAL_TABLE 当前位置
        self.resetPC(self.currentPtr)
        # 临时记录 currentPtr
        tmpAddr = self.currentPtr
        # 修改值
        self.patchList(self.calOffsetToList(0, mPtr))
        # 修改后指针加一赋值给 AsmCommon 中的 currentPtr（下次使用）
        self.currentPtr = self.currentPC
        # 恢复修改后的jumper中的 currentPC
        self.currentPC = self._lastPC
        # 记录在在字典中 mapPtr
        self.mapPtr.setdefault(tmpAddr, mPtr)
        # print("[*] Added Ptr {} ---> {}".format(hex(tmpAddr), hex(mPtr)))
        return tmpAddr

    def getStr(self, mStr):
        # 查找已有字符串的情况，不再走添加流程
        for itemC in self.mapStr.items():
            if itemC[1] == mStr:
                print("[*] Get string at " + str(hex(itemC[0])) + "\t" + mStr)
                return itemC[0]
                # for itemP in self.mapPtr.items():
                #     if itemP[1] == itemC[0]:
                #         return itemP[0]
        # 保存jumper中的currentPC
        self._lastPC = self.currentPC
        # 字符编码为 utf-8
        listStr = list(mStr.encode(encoding="utf-8"))
        # 字符串末尾补零
        listStr.append(0x0)
        # 四字节对齐
        # for i in range(0, 4 - listStr.__len__() % 4):
        #     listStr.append(0x0)
        # 修改jumper中的保存jumper中的currentPC指向 STR_TABLE 当前位置
        self.resetPC(self.currentStr)
        # 临时记录 currentPtr 字符串开始位置
        tmpAddr = self.currentStr
        # 存入String的值
        self.patchList(listStr)
        # 记录在在字典中 mapStr
        self.mapStr.setdefault(tmpAddr, mStr)
        # 修改后指针加一赋值给 AsmCommon 中的 currentStr（下次使用）
        self.currentStr = self.currentPC
        # 恢复修改后的jumper中的 currentPC
        self.currentPC = self._lastPC
        # 保存 string 到 GLOBAL_TABLE
        self.getPtr(self.currentStr - listStr.__len__())
        print("[*] Create string at " + str(hex(tmpAddr)) + "\t" + mStr)
        return tmpAddr

    def getAddrByExpName(self, expName):
        return self.lf.get_symbol(expName).value

    def getRelocation(self, expName):
        return self.lf.get_relocation(expName).address

    # 调用 addHook 之后 currentPC 指向了我们写代码的位置
    def addHook(self, fromPtr, jmpType="LDR", printTips=True, printRegs=False, fpReg="R11"):
        self._recordFromToLOG = [fromPtr, self.currentTramp, jmpType]
        if hookedFunctions.get(fromPtr) is not None:
            raise Exception("Ptr:{} is Already Hooked".format(hex(fromPtr)))

        if jmpType in ("BL", "BLX", "B", "BEQ", "BNE"):
            self.checkJmpRange(self._recordFromToLOG[0], self._recordFromToLOG[1])
        print("addHook {} ---> {}\t{}\n----------".format(hex(self._recordFromToLOG[0]), hex(self._recordFromToLOG[1]),
                                                          self._recordFromToLOG[2]))

        self.jumpTo(self.currentTramp, fromPtr, codeIndex=0, jmpType=jmpType, reg="R12", resetPC=True, resetBackPC=True)
        self.saveEnv()
        if printTips:
            self.jumpTo(self.getSymbolByName("prepareArgs", mPtr=fromPtr), jmpType="BL", resetPC=False)
            self.jumpTo(self.getSymbolByName("printTips", mPtr=fromPtr), jmpType="BL", resetPC=False)
        # 读取hook时候的registers
        if printRegs:
            self.jumpTo(self.getSymbolByName("printRegs", fpReg=fpReg), jmpType="BL", resetPC=False)
        # 跳转真实hook代码
        self.jumpTo(self.currentCodes, jmpType="BL", resetPC=False)
        self.restoreEnv()
        self.restoreCode(codeIndex=0, fromAddress=fromPtr)
        self.jumpTo(self._jumpBackPC, fromAddress=self.currentPC, jmpType=jmpType, reg="R12", resetPC=False)
        self.currentTramp = self.currentPC
        self.currentPC = self.currentCodes
        self.patchASM("STMFD SP!, {LR}")

    def endHook(self):
        self.patchASM("LDMFD SP!, {PC}")
        self.currentCodes = self.currentPC
        hookedFunctions.setdefault(self._recordFromToLOG[0], self._recordFromToLOG[1])
        print("--------------------------------------------------------------------------")

    # 获取进入hook之前的寄存器值
    # r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, CPSR, SP
    # CPSP SP r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr
    def getArg(self, regIndex=0, toReg="R0", defFP="R11"):
        index = 4 * (regIndex + 2)
        if index > 4 * 17:
            raise Exception("ArrayIndexOutOfBoundsException")
        elif index == 4 * 15:
            index = 0
        elif index == 4 * 16:
            index = 4 * 1
        self.patchASM("LDR {},[{},#{}]".format(toReg, defFP, index))

    # 修改进入hook之前的reg值(r0 write back to r12[regIndex])
    def setArg(self, regIndex=0, fromReg="R0", defFP="R11"):
        index = 4 * (regIndex + 1)
        if index > 4 * 15:
            raise Exception("ArrayIndexOutOfBoundsException")
        elif index == 4 * 15:
            index = 0
        self.patchASM("STR {},[{},#{}]".format(fromReg, defFP, index))

    def saveRegToStack(self, reg="R0", index=0):
        self.patchASM("STR {},[SP,#{}]".format(reg, self._pSize * index))

    def prepareStack(self, useSpCount=10):
        self.patchASM("SUB SP,SP,#{}".format(self._pSize * useSpCount))
        self._AllocSpSize = useSpCount

    def restoreStack(self, useSpCount=None):
        if useSpCount is None:
            useSpCount = self._AllocSpSize
        self.patchASM("ADD SP,SP,#{}".format(self._pSize * useSpCount))

    def getSymbolByName(self, name, mPtr=None, fpReg="R11"):

        def prepareFunctions():
            if functionsMap.get(str(name)) is None and name == "printRegs":
                tmpPC = self.currentPC
                self.resetPC(self.currentCodes)
                self.recordSymbol("printRegs", self.currentPC)
                self.patchASM("STMFD SP!, {LR}")
                self.prepareStack(15)
                # ANDROID_LOG_UNKNOWN = 0 ANDROID_LOG_DEFAULT = 1 ANDROID_LOG_VERBOSE = 2 ANDROID_LOG_DEBUG = 3 ANDROID_LOG_INFO = 4 ANDROID_LOG_WARN = 5 ANDROID_LOG_ERROR = 6 ANDROID_LOG_FATAL = 7 ANDROID_LOG_SILENT = 8
                self.patchASM("MOV {},#{}".format("R0", 6))
                # R0=>3 R1=>p"ZZZ" R2=>p"---> %p %p %p %p" R3=>R0 SP=>R1 SP,[#4]=>R2 SP,[#8]=>R3
                self.loadToReg(self.getStr("ZZZ"), reg="R1")
                self.loadToReg(self.getStr(
                    " \n\t\tR0~R3:\t%p %p %p %p \n\t\tR4~R10:\t%p %p %p %p %p %p %p \n\t\tFP:%p IP:%p LR:%p SP:%p CPSR:%p".format(
                        hex(0))),
                    reg="R2")
                if fpReg != "R11":
                    self.patchASM("MOV R11,{}".format(fpReg))
                self.patchASM("ADD R3,R11,#{}".format(3 * 4))
                self.patchASM("LDMIA R3,{R4,R5,R6,R7,R8,R9,r10}")
                self.patchASM("STMIA SP,{R4,R5,R6,R7,R8,R9,r10}")
                self.patchASM("ADD R3,R11,#{}".format(3 * 4 + 7 * 4))
                self.patchASM("LDMIA R3,{R4,R5,R6,R7,R8,R9}")
                self.patchASM("ADD R3,SP,#{}".format(7 * 4))
                self.patchASM("STMIA R3,{R4,R5,R6,R7,R8,R9}")
                self.getArg(regIndex=14, toReg="R4")
                self.getArg(regIndex=13, toReg="R5")
                self.patchASM("ADD R3,SP,#{}".format((6 + 7) * 4))
                self.patchASM("STMIA R3,{R4,R5}")
                self.getArg(regIndex=0, toReg="R3")
                self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)
                self.restoreStack(15)
                self.patchASM("LDMFD SP!, {PC}")
                self.currentCodes = self.currentPC
                self.resetPC(tmpPC)
            elif mPtr is not None and name == "printTips":
                tmpPC = self.currentPC
                tmpCode = self.currentCodes
                self.resetPC(self.currentCodes)
                self.recordSymbol("printTips", self.currentPC)
                self.patchASM("STMFD SP!, {LR}")
                self.prepareStack(1)
                self.patchASM("MOV {},#{}".format("R0", 6))
                self.loadToReg(self.getStr("ZZZ"), reg="R1")
                if mPtr in functionsMap.values():
                    self.loadToReg(self.getStr("Called %s at %p"), reg="R2")
                else:
                    self.loadToReg(self.getStr("Called %p ---> %p"), reg="R2")
                self.patchASM("LDR R4,[R4]")
                self.saveRegToStack("R4", index=0)
                self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)
                self.restoreStack()
                self.patchASM("LDMFD SP!, {PC}")
                self.currentCodes = self.currentPC
                self.resetPC(tmpPC)
                return tmpCode
            elif mPtr is not None and name == "prepareArgs":
                tmpPC = self.currentPC
                tmpCode = self.currentCodes
                self.resetPC(self.currentCodes)
                self.patchASM("STMFD SP!, {LR}")
                if mPtr in functionsMap.values():
                    for item in functionsMap.items():
                        if item[1] == mPtr:
                            self.loadToReg(self.getStr(item[0]), reg="R3")
                            self.loadToReg(self.getPtr(item[1]), reg="R4")
                            break
                else:
                    self.loadToReg(self.addGOT(mPtr=mPtr), reg="R3")
                    self.patchASM("LDR R3,[R3]")
                    self.loadToReg(self.getPtr(mPtr), reg="R4")
                    # self.patchASM("LDR R4,[R4]")
                self.patchASM("LDMFD SP!, {PC}")
                self.currentCodes = self.currentPC
                self.resetPC(tmpPC)
                return tmpCode
        tmpRet = prepareFunctions()
        return tmpRet if tmpRet is not None else functionsMap.get(str(name))

    @staticmethod
    def getGotByName(name):
        if name is not None:
            return gotMap.get(str(name))

    @staticmethod
    def recordSymbol(name, ptr):
        functionsMap.setdefault(name, ptr)
        print("[*] recordSym ---> {}\t{}".format(str(name).ljust(15, " "), hex(ptr)))


class CommonBase(JumperBase):
    def __init__(self, filePath, ARCH=ARCH_ARM):
        JumperBase.__init__(self, filePath, ARCH=ARCH_ARM)
        print("--------------------------------------------------------------------------")
        self.hookInit()

    def hookInit(self, log=True):
        if self.lf.ctor_functions[0] is None:
            raise Exception("There is no ctor_functions")
        # 修改权限
        try:
            self.addHook(self.lf.ctor_functions[0].value, jmpType="B", printTips=False, printRegs=False)
        except:
            self.addHook(self.lf.ctor_functions[0].value, jmpType="LDR", printTips=False, printRegs=False)

        # 这个size其实可以填的很大，即使返回了-1，但是它是按照页来修改访问属性的，问题不大，所以返回-1表示我们已经覆盖了全部（超出了）
        self.fixGot(log=log)

    def fixGot(self, log):
        self.mprotect(mPtr=functionsMap.get("GLOBAL_TABLE"), size=configSize["mProtect_size"], log=log)
        self.loadBaseToReg(reg="R9", log=True)
        self.relocationGot(reg="R9")
        self.endHook()

    # 获取 il2cpp base address
    # 代码执行到这里的时候我们知道当前的pc值以及当前代码静态的地址，所以我们相减即可得到当前的so基地址
    def loadBaseToReg(self, reg="R4", log=False):
        self.loadToReg(self.getPtr(self.currentPC + 7 * self._pSize), reg="R1")
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
        self.loadToReg(functionsMap.get("GOT_TABLE"), reg="R5")
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
            self.loadToReg(self.getPtr(mPtr), reg="R2")
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

    def strcmp(self, str0, str1, reg0="R0", reg1="R1"):
        if str(str0).startswith("R"):
            # str0 填写 register 的情况
            self.patchASM("MOV {},{}".format(reg0, str0))
        elif type(str0) is str:
            # 填写一个具体的字符串的情况
            self.loadToReg(self.getStr(str0), reg=reg0)
        if str(str1).startswith("R"):
            self.patchASM("MOV {},{}".format(reg0, str0))
        elif type(str1) is str:
            self.loadToReg(self.getStr(str1), reg=reg1)
        self.jumpTo(self.getRelocation("strcmp"), jmpType="REL", reg="R3", resetPC=False)

    def android_log_print_msg(self, prio=3, tag="ZZZ", msg="Called"):
        self.patchASM("MOV R0, #{}".format(prio))
        self.loadToReg(self.getStr(tag), reg="R1")
        self.loadToReg(self.getStr(msg), reg="R2")
        self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R3", resetPC=False)

    # 依次对R3,sp,sp#4,sp#8... 进行参数传递
    def android_log_print_reg(self, prio=3, tag="ZZZ", formart="---> %p"):
        self.patchASM("MOV R0, #{}".format(prio))
        self.loadToReg(self.getStr(tag), reg="R1")
        self.loadToReg(self.getStr(formart), reg="R2")
        self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)

    def callFunction(self, mPtr, *args):

        def load4Reg():
            for i in range(0, len(args)):
                if type(args[i]) == str:
                    self.loadToReg(self.getStr(args[i]), "R{}".format(i - 1))
                elif type(args[i]) == int:
                    self.patchASM("MOV R{},{}".format("R{}".format(i - 1), args[i]))

        if len(args) <= 4:
            load4Reg()
            self.jumpTo(mPtr, jmpType="BL", resetPC=False)
        else:
            load4Reg()
            # todo 多余的参数压栈调用
            pass

        self.jumpTo(mPtr, jmpType="BL", resetPC=False)

    def addBP(self, mPtr):
        tmpPC = self.currentPC
        self.resetPC(mPtr)
        # FE FF FF EA    死循环
        self.patchASM("b #0")
        self.resetPC(tmpPC)


class UnityJumper(CommonBase):

    def __init__(self, filePath, ARCH=ARCH_ARM):
        CommonBase.__init__(self, filePath, ARCH=ARCH)
        # gotMap add Got Functions
        for item in functionsMap.items():
            self.addGOT(int(item[1]), item[0])

    def hookInit(self, log=True):
        try:
            self.addHook(self.lf.get_symbol("il2cpp_init").value, jmpType="B", printTips=False, printRegs=False)
        except:
            self.addHook(self.lf.get_symbol("il2cpp_init").value, jmpType="LDR", printTips=False, printRegs=False)
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
            # struct jValue只需要四字节，但是内存展现给我们的感觉是一个数组项占用了8字节，且前四字节似乎只是标识这个后面的四字节是否使用一样的感觉
            tmpList.extend([0x1, 0x00, 0x00, 0x00])
            if type(args[index]) is int:
                tmpList.extend(self.calOffsetToList(0, args[index], 0))
            elif type(args[index]) is str:
                tmpList.extend(self.calOffsetToList(0, self.getStr(args[index]), 4))
            elif type(args[index]) is bool:
                tmpList.extend([0x1 if args[index] else 0x0, 0x00, 0x00, 0x00])
        tmpList.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # 0填充
        self.patchList(tmpList)
        self.currentStr = self.currentStr + len(tmpList)
        print("[*] Create JValueArray {} ---> {}".format(hex(tmpRetPtr), tmpList))
        self.currentPC = tmpCPC
        return tmpRetPtr

    def getUnityStr(self, mStr):
        self.loadToReg(self.getStr(mStr), "R0")
        try:
            self.jumpTo(functionsMap.get("il2cpp_string_new"), jmpType="BL", resetPC=False)
        except:
            self.jumpTo(functionsMap.get("il2cpp_string_new"), jmpType="REG", resetPC=False)

    def FindClass(self, clsName):
        self.getUnityStr(clsName)
        try:
            self.jumpTo(functionsMap.get("FindClass"), jmpType="BL", resetPC=False)
        except:
            self.jumpTo(functionsMap.get("FindClass"), jmpType="REG", resetPC=False)
        self.patchASM("MOV R4,R0")

    def GetStaticMethodID(self, funcName, sign):
        self.getUnityStr(funcName)
        self.patchASM("MOV R5,R0")
        self.getUnityStr(sign)
        self.patchASM("MOV R6,R0")
        self.patchASM("MOV R0,R4")
        self.patchASM("MOV R1,R5")
        self.patchASM("MOV R2,R6")
        try:
            self.jumpTo(functionsMap.get("GetStaticMethodID"), jmpType="BL", resetPC=False)
        except:
            self.jumpTo(functionsMap.get("GetStaticMethodID"), jmpType="REG", resetPC=False)
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
            try:
                self.jumpTo(functionsMap.get("CallStaticVoidMethod"), jmpType="BL", resetPC=False)
            except:
                self.jumpTo(functionsMap.get("CallStaticVoidMethod"), jmpType="REG", resetPC=False)

    def setFunctionRet(self, pFunction, pRet):
        self.resetPC(pFunction)
        self.patchASM("MOV R0, #{}".format(pRet))
        self.nop(self.currentPC)

    def nop(self, pFunction):
        self.resetPC(pFunction)
        self.patchASM("BX LR")


class MergeUtils:
    def __init__(self, path1, path2=r"C:\Users\pc\AndroidStudioProjects\liefInject\app\release\libinject.so"):
        self.path1 = path1
        self.path2 = path2
        self.offset = None
        self.lf_1 = lief.parse(path1)
        self.lf_2 = lief.parse(path2)
        self.text = self.lf_1.get_section(".text")
        self.vAddr = None
        self.section = None

    def mergeSecs(self):
        self.vAddr = -1
        return {".text": self.mergeSection(".text"),
                ".rodata": self.mergeSection(".rodata"),
                ".data": self.mergeSection(".data")}

    def recordCommon(self):
        # 记录合并后需要用到的导出地址
        self.recordSymbol("GLOBAL_TABLE", self.getSym2("GLOBAL_TABLE"))
        self.recordSymbol("STR_TABLE", self.getSym2("STR_TABLE"))
        self.recordSymbol("GOT_TABLE", self.getSym2("GOT_TABLE"))
        self.recordSymbol("trampolines", self.getSym2("trampolines"))
        self.recordSymbol("textCodes", self.getSym2("textCodes"))

        # 导出函数初始化
        self.recordSymbol("il2cpp_init", self.getSym1("il2cpp_init"), fix=False)
        self.recordSymbol("il2cpp_alloc", self.getSym1("il2cpp_alloc"), fix=False)
        self.recordSymbol("il2cpp_free", self.getSym1("il2cpp_free"), fix=False)
        self.recordSymbol("il2cpp_string_new", self.getSym1("il2cpp_string_new"), fix=False)
        print("--------------------------------------------------------------------------")

    # 合并整个段
    def mergeSeg(self):
        # self.lf_1.add_exported_function(0x5465D8, "SettingsMenuIn")
        self.vAddr = self.lf_1.add(self.lf_2.segments[1]).virtual_address
        print("[*] mergeSeg => " + self.lf_2.segments[1] + " => " + self.vAddr)
        retPath = self.save("libil2cpp_merge.so")
        self.recordCommon()
        return retPath

    # 合并指定节
    def mergeSection(self, section=".text"):
        # 添加了导出函数就会崩溃
        self.section = section

        tmpList = []
        for index in range(0, configSize["GOT_TABLE_fill"]):
            tmpList += [0x0, 0x0, 0x0, 0x0]
        self.lf_2.patch_address(self.lf_2.get_symbol("GOT_TABLE").value, tmpList)
        self.lf_2.write(r"C:\Users\pc\AppData\Local\Temp\libinjectTMP.so")
        self.lf_2 = lief.parse(r"C:\Users\pc\AppData\Local\Temp\libinjectTMP.so")

        # 先保存一下再打开重新回去vAddr
        self.text = self.text
        tempOff = self.lf_1.get_section(".text").virtual_address
        self.lf_1.add(self.lf_2.get_section(section))
        retPath = self.save("libil2cpp_merge.so")

        self.offset = self.text.virtual_address - tempOff
        injectSize = self.text.size
        self.vAddr = self.lf_1.get_section(section).virtual_address
        print("--------------------------------------------------------------------------")
        print("[*] mergeSection => " + section + " => " + str(hex(self.vAddr)))
        print("--------------------------------------------------------------------------")
        self.recordCommon()
        return retPath

    def getSym1(self, symName):
        return self.lf_1.get_symbol(symName).value

    def getSym2(self, symName):
        if self.section is None:
            return self.vAddr + self.lf_2.get_symbol(symName).value
        else:
            return self.vAddr + (
                    self.lf_2.get_symbol(symName).value - self.lf_2.get_section(self.section).virtual_address)

    def recordSymbol(self, name, ptr, fix=True):
        if str(name) in ("GLOBAL_TABLE", "STR_TABLE", "trampolines", "textCodes", "GOT_TABLE") or not fix:
            functionsMap.setdefault(name, ptr)
            print("[*] recordSym ---> {}\t{}".format(str(name).ljust(15, " "), hex(ptr)))
        else:
            functionsMap.setdefault(name, ptr + self.offset)
            print("[*] recordSym ---> {}\t{} ---> {}".format(str(name).ljust(25, " "), hex(ptr).ljust(10, " "),
                                                             hex(ptr + self.offset)))

    def recordSymbols(self, maps):
        for name in maps.keys():
            self.recordSymbol(name, maps.get(name))
        print("-------------------------------------")

    @staticmethod
    def getSymbolByName(name):
        return functionsMap.get(name)

    def save(self, name="libil2cppN.so"):
        savePath = os.path.dirname(self.path1) + "/" + name
        self.lf_1.write(savePath)
        return savePath
