import os

import capstone
import lief
from keystone import keystone

from Config import ARCH_ARM, functionsMap, configSize, gotMap, hookedFunctions, ARCH_ARM64, preFuncMap


class AsmPatcher:

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
        self._AllocSpSize = 0
        self._lastPC = 0
        self._jumpBackPC = 0
        self._returnAddr = 0
        self._codeContainer = [[], [], [], [], [], [], [], [], []]
        self._extraFixData = [{}, {}, {}, {}, {}, {}, {}, {}, {}]
        self._recordFromToLOG = []

        if ARCH == ARCH_ARM:
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        elif ARCH == ARCH_ARM64:
            # self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            # self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_ARM)
            raise Exception("Todo  -.-")
        else:
            raise Exception("Todo  -.-")

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

    def patchASM(self, asm="nop", labName=None):
        if labName is not None:
            self.preLabel(labName)
        self.patchList(self.ks.asm(asm)[0])

    def preLabel(self, labName):
        preFuncMap[0].setdefault(labName, self.currentPC)

    # use like this " B #lable1 /bne #lable2 "
    def preAsm(self, asm="nop", label=None):
        if label is not None:
            self.preLabel(label)
        preFuncMap[1].setdefault(asm, self.currentPC)
        self.patchASM("nop")

    def enableAsm(self):
        for func in preFuncMap[1].items():
            opStr = str(func[0]).split("#")[0]
            opSub = str(func[0]).split("#")[1]
            opNum = 0
            for label in preFuncMap[0].items():
                if label[0] == opSub:
                    opNum = self.calOffset(func[1], label[1], offset=0)
            if opNum == 0:
                raise Exception("Label Not Found")
            tmpPC = self.currentPC
            self.resetPC(func[1])
            self.patchASM("{} #{}".format(opStr, opNum))
            self.currentPC = tmpPC
        preFuncMap.clear()

    def saveEnv(self, fpReg="R11", simple=False):
        if not simple:
            self.patchASM("push {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")
            self.patchASM("MRS R11, CPSR")
            self.patchASM("MOV R12, SP")
            self.patchASM("STMFD SP!, {R11,R12}")
            self.patchASM("MOV {},SP".format(fpReg))
        else:
            self.patchASM("push {r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")

    def restoreEnv(self, simple=False):
        if not simple:
            self.patchASM("LDMFD SP!, {R11,R12}")
            self.patchASM("MSR CPSR, R11")
            self.patchASM("pop {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")
        else:
            self.patchASM("pop {r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, pc}")

    def saveCode(self, codeIndex=0, insLength=3, fromPtr=None):
        if fromPtr is None:
            fromPtr = self.currentPC
        self._codeContainer[codeIndex] = self.lf.get_content_from_virtual_address(fromPtr, self._pSize * insLength)

    def restoreCode(self, codeIndex=0, needFix=True):

        def getType(insStr):
            # 修复 LDR (其实这一步的修复也可以像后面一样直接把pc用r12来替换) / LDR R0, =(byte_125A8C9 - 0x357B18)
            if insStr.find("ldr") != -1 and insStr.find("pc") != -1 and insStr.find("#") != -1:
                return "ldr1"
            # 修复 LDR / LDR R0, [PC,R0]
            elif insStr.find("ldr") != -1 and insStr.find("pc") != -1 and insStr.find("#") == -1:
                return "ldr2"
            # MOV/ADD/SUB PC 相关的指令
            elif (insStr.find("mov") != -1 or insStr.find("add") != -1 or insStr.find("sub") != -1) and insStr.find(
                    "pc") != -1:
                return "fixPC"
            # 修复 BNE/BEQ
            elif insStr.find("bne") == 0 or insStr.find("beq") == 0:
                return "fixBneBeq"
            # 修复 BL/BLX and 修复 B/BX (排除 bl rx的情况)
            elif ((insStr.find("bl") != -1 or insStr.find("blx") != -1) or (
                    insStr.find("b") != -1 or insStr.find("bx") != -1)) and insStr.find("r") == -1:
                return "fixBJmp"
            else:
                return "default"

        # 修复该条指令需要用到几条指令
        def getTypePatchSize(insStr):
            tmpType = getType(insStr)
            if tmpType == "default": return 1
            if tmpType == "ldr1": return 3
            if tmpType == "ldr2": return 4
            if tmpType == "fixPC": return 7
            if tmpType == "fixBneBeq": return 2
            if tmpType == "fixBJmp": return 1

        def fixLDR(insStr):
            # tmpCodeContainer.extend(self.ks.asm(tmpInsList[index].replace("pc", "r12"))[0])
            tmpLdrPC = self._extraFixData[codeIndex]["fromAddress"] + self._pSize * (index + 2) + eval(
                insStr[insStr.find("#") + 1:insStr.find("]")])
            tmpReg = insStr[insStr.find("ldr ") + 4:insStr.find(", [")]
            self.patchASM("LDR {}, [PC,#0]".format(tmpReg))
            self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
            self.patchList(self.calOffsetToList(self.currentPC - 4, tmpLdrPC, 1))

        def fixPC(insStr):
            # 零时用一下就懒得移动SP，直接把R12放在SP的上面
            self.patchASM("STR R12,[SP,#-0x4]")
            fixAddr = self.addGOT(self._extraFixData[codeIndex]["fromAddress"] + self._pSize * (index + 2))
            self.loadToReg(fixAddr, toReg="R12")
            self.patchASM("LDR R12,[R12]")
            self.patchASM(insStr.replace("pc", "r12"))
            self.patchASM("LDR R12,[SP,#-0x4]")

        def fixBeqBne(insStr):
            tmpOffset = insStr.split("#")[1]
            if insStr.find("beq") == 0:
                tItem = insStr.replace("beq", "bne").replace(tmpOffset, hex(self._pSize * 4))
            else:
                tItem = insStr.replace("bne", "beq").replace(tmpOffset, hex(self._pSize * 4))
            self.patchASM(tItem)
            tmpToAddr = self._extraFixData[codeIndex]["fromAddress"] + self._pSize * index + eval(tmpOffset) - configSize["offset"]
            self.jumpTo(tmpToAddr - self._pSize * 2, jmpType="LDR", resetPC=False)

        def fixBJmp(insStr):
            # eval(item.split("#")[1]) 原本的 BL 已经被修正过了，所以这里得修复一下跳转 多了一次offset （- configSize["offset"]）
            toAddress = self._extraFixData[codeIndex]["fromAddress"] + self._pSize * index + eval(
                insStr.split("#")[1]) - configSize["offset"]
            jmpType = "REG" if (insStr.find("bl") != -1 or insStr.find("blx") != -1) else "LDR"
            # 默认计算了pc偏移的，然而bl本身就是一个简单的加法，所以这里的toAddress需要减去2个_pSize
            self.jumpTo(toAddress - self._pSize * 2, jmpType=jmpType, reg="R12", resetPC=False)

        def default(insStr):
            self.patchASM(insStr)

        operation = {'ldr1': fixPC,  # fixLDR
                     'ldr2': fixPC,
                     'fixPC': fixPC,
                     'fixBneBeq': fixBeqBne,
                     'fixBJmp': fixBJmp,
                     'default': default
                     }
        tmpInsList = self.getAsmFromList(self._codeContainer[codeIndex])
        if needFix:
            # 逐条解析保存的指令并修复指令
            for index in range(0, len(tmpInsList)):
                operation[getType(tmpInsList[index])](tmpInsList[index])
        else:
            self.patchList(self._codeContainer[codeIndex])

    def save(self, name=None):
        # 检查范围
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
            path = os.path.dirname(self.filePath) + "\\" + name
        self.lf.write(path)
        print("\nSave libil2cpp.so to " + path)
        return path

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

        # BL 跳转范围操过,修改跳转方式为 REG
        if jmpType == "BL" or jmpType == "B":
            try:
                self.checkJmpRange(fromAddress, toAddress)
            except:
                _jmpType = "REG" if jmpType == "BL" else "LDR"
                tmpStr = hex(fromAddress) + " ---> " + hex(toAddress) + "\t" + jmpType + " ---> " + _jmpType
                jmpType = _jmpType
                print("[*] Fixed {}".format(tmpStr))

        # 记录原本被替换的AsmCode
        def SaveCode():
            if jmpType == "B" or jmpType == "BL":
                # 记录函数返回地址
                if resetBackPC:
                    self._jumpBackPC = fromAddress + self._pSize * 1
                if codeIndex != -1:
                    self.saveCode(codeIndex, 1)
            elif jmpType == "LDR":
                if resetBackPC:
                    self._jumpBackPC = fromAddress + self._pSize * 3
                if codeIndex != -1:
                    self.saveCode(codeIndex, 3)

            self._extraFixData[codeIndex] = {"fromAddress": fromAddress, "toAddress": toAddress, "jmpType": jmpType,
                                             "reg": reg, "resetPC": resetPC, "resetBackPC": resetBackPC,
                                             "showLog": showLog}

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

        def JMP_LDR():
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 3
            self.patchASM("LDR {},[PC]".format(reg))
            self.patchASM("ADD PC,{}".format(reg))
            self.patchList(self.calOffsetToList(self.currentPC - 4, toAddress))  # 起点算的是pc的位置(上一条)，而不是当前位置

            if showLog:
                print('\n[*] Patch Code TYPE : JMP_LDR')
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

        switch = {'LDR': JMP_LDR,  # 远距离的B
                  'REG': JMP_REG,  # 远距离的BL
                  'REL': JMP_REL,  # 跳转GOT
                  'BEQ': JMP_BEQ,
                  'BNE': JMP_BNE,
                  'BL': JMP_BL,
                  'B': JMP_B}
        switch.get(jmpType, JMP_B)()
        if resetPC:
            self.currentPC = toAddress

    def loadToReg(self, mPtr, toReg="R0", fix=1):
        self.patchASM("LDR {}, [PC,#4]".format(toReg))
        self.patchASM("ADD {}, PC, {}".format(toReg, toReg))
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

    def getStr(self, mStr, useCache=True):
        # 查找已有字符串的情况，不再走添加流程
        if useCache:
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
    def addHook(self, fromPtr, jmpType="LDR", printTips=True, printRegs=False):
        self._recordFromToLOG = [fromPtr, self.currentTramp, jmpType]
        if hookedFunctions.get(fromPtr) is not None:
            raise Exception("Ptr:{} is Already Hooked".format(hex(fromPtr)))

        print("addHook {} ---> {}\t{}\n----------".format(hex(self._recordFromToLOG[0]), hex(self._recordFromToLOG[1]),
                                                          self._recordFromToLOG[2]))

        self.jumpTo(self.currentTramp, fromPtr, codeIndex=0, jmpType=jmpType, reg="R12", resetPC=True, resetBackPC=True)
        self.saveEnv()
        if printTips:
            self.jumpTo(self.getSymbolByName("printTips", mPtr=fromPtr), jmpType="BL", resetPC=False)
        # 读取hook时候的registers
        if printRegs:
            self.jumpTo(self.getSymbolByName("printRegs"), jmpType="BL", resetPC=False)
        # 跳转真实hook代码
        self.jumpTo(self.currentCodes, jmpType="BL", resetPC=False)
        self.restoreEnv()
        self.restoreCode(codeIndex=0)
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
    #      0   1   2   3   4   5   6   7   8   9  10  11  12  13   14   15
    # 期望 r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, CPSR, SP
    # 实际 CPSP SP r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr
    def getArg(self, regIndex=0, toReg="R0", defFP="R11"):
        if regIndex not in range(0, 16):
            raise Exception("ArrayIndexOutOfBoundsException")
        offset = 4 * (regIndex + 2) if regIndex < 14 else 4 * (regIndex - 14)
        self.patchASM("LDR {},[{},#{}]".format(toReg, defFP, offset))

    # 修改进入hook之前的reg值(r0 write back to r12[regIndex])
    def setArg(self, regIndex=0, fromReg="R0", defFP="R11"):
        if regIndex not in range(0, 16):
            raise Exception("ArrayIndexOutOfBoundsException")
        offset = 4 * (regIndex + 2) if regIndex < 14 else 4 * (regIndex - 14)
        self.patchASM("STR {},[{},#{}]".format(fromReg, defFP, offset))

    def saveRegToStack(self, reg="R0", index=0):
        self.patchASM("STR {},[SP,#{}]".format(reg, self._pSize * index))

    def prepareStack(self, useSpCount=10):
        self.patchASM("SUB SP,SP,#{}".format(self._pSize * useSpCount))
        self._AllocSpSize = useSpCount

    def restoreStack(self, useSpCount=None):
        if useSpCount is None:
            useSpCount = self._AllocSpSize
            self._AllocSpSize = None
        self.patchASM("ADD SP,SP,#{}".format(self._pSize * useSpCount))

    def getSymbolByName(self, name, mPtr=None):

        def prepareFunctions():
            # 只构建一次,后续再用到都直接返回函数地址
            if functionsMap.get(str(name)) is None and name == "printRegs":
                tmpPC = self.currentPC
                self.resetPC(self.currentCodes)
                self.recordSymbol("printRegs", self.currentPC)
                self.saveEnv(simple=True)
                # 一共十六个参数 R3传递一个参数 剩下的15个使用堆栈
                self.prepareStack(15)
                # ANDROID_LOG_UNKNOWN = 0 ANDROID_LOG_DEFAULT = 1 ANDROID_LOG_VERBOSE = 2 ANDROID_LOG_DEBUG = 3 ANDROID_LOG_INFO = 4 ANDROID_LOG_WARN = 5 ANDROID_LOG_ERROR = 6 ANDROID_LOG_FATAL = 7 ANDROID_LOG_SILENT = 8
                self.patchASM("MOV {},#{}".format("R0", 6))
                # R0=>3 R1=>p"ZZZ" R2=>p"---> %p %p %p %p" R3=>R0 SP=>R1 SP,[#4]=>R2 SP,[#8]=>R3
                self.loadToReg(self.getStr("ZZZ"), toReg="R1")
                self.loadToReg(self.getStr(
                    " \n\t\tR0~R3:\t%p %p %p %p \n\t\tR4~R10:\t%p %p %p %p %p %p %p \n\t\tFP:%p IP:%p LR:%p SP:%p CPSR:%p"),
                    toReg="R2")
                # R11/FP + 3*pSize -> R3
                # 结合 def getArg(self, regIndex=0, toReg="R0", defFP="R11") 上面的堆栈情况注释来看这段代码
                self.patchASM("ADD R3,R11,#{}".format(3 * self._pSize))
                self.patchASM("LDMIA R3,{R4,R5,R6,R7,R8,R9,r10}")
                self.patchASM("STMIA SP,{R4,R5,R6,R7,R8,R9,r10}")
                self.patchASM("ADD R3,R11,#{}".format(3 * self._pSize + 7 * self._pSize))
                self.patchASM("LDMIA R3,{R4,R5,R6,R7,R8,R9}")
                self.patchASM("ADD R3,SP,#{}".format(7 * self._pSize))
                self.patchASM("STMIA R3,{R4,R5,R6,R7,R8,R9}")
                self.getArg(regIndex=14, toReg="R4")
                self.getArg(regIndex=13, toReg="R5")
                self.patchASM("ADD R3,SP,#{}".format((6 + 7) * self._pSize))
                self.patchASM("STMIA R3,{R4,R5}")
                self.getArg(regIndex=0, toReg="R3")
                self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)
                self.restoreStack(15)
                self.restoreEnv(simple=True)
                self.currentCodes = self.currentPC
                self.resetPC(tmpPC)
            # 每个函数参数不一致每次构建不同的并返回(如果想让它一直,那前面必然有一个堆栈或者是内存读写,还是会多一个调用)
            elif mPtr is not None and name == "printTips":
                tmpPC = self.currentPC
                tmpCode = self.currentCodes
                self.resetPC(self.currentCodes)
                self.recordSymbol("printTips", self.currentPC)
                self.saveEnv(simple=True)
                # 准备参数
                if mPtr in functionsMap.values():
                    for item in functionsMap.items():
                        if item[1] == mPtr:
                            self.loadToReg(self.getStr(item[0]), toReg="R3")
                            self.loadToReg(self.getPtr(item[1]), toReg="R4")
                            break
                else:
                    self.loadToReg(self.addGOT(mPtr=mPtr), toReg="R3")
                    self.patchASM("LDR R3,[R3]")
                    self.loadToReg(self.getPtr(mPtr), toReg="R4")
                # 准备日志调用
                self.prepareStack(1)
                self.patchASM("MOV {},#{}".format("R0", 6))
                self.loadToReg(self.getStr("ZZZ"), toReg="R1")
                if mPtr in functionsMap.values():
                    self.loadToReg(self.getStr("Called %s at %p"), toReg="R2")
                else:
                    self.loadToReg(self.getStr("Called %p ---> %p"), toReg="R2")
                self.patchASM("LDR R4,[R4]")
                self.saveRegToStack("R4", index=0)
                self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg="R4", resetPC=False)
                self.restoreStack(1)
                self.restoreEnv(simple=True)
                self.currentCodes = self.currentPC
                self.resetPC(tmpPC)
                return tmpCode

        tmpRet = prepareFunctions()
        return tmpRet if tmpRet is not None else functionsMap.get(str(name))

    def setFunctionRet(self, pFunction, pRet):
        self.resetPC(pFunction)
        self.patchASM("MOV R0, #{}".format(pRet))
        self.nop(self.currentPC)

    def nop(self, pFunction):
        self.resetPC(pFunction)
        self.patchASM("BX LR")

    def addBP(self, mPtr=None):
        if mPtr is not None:
            self.resetPC(self.currentPC)
        # FE FF FF EA    死循环
        self.patchASM("b #0")

    @staticmethod
    def checkJmpRange(ptrFrom, ptrTo):
        # B指令和BL指令最大跳转距离是 ±32M (bits[23:0]是立即数空间,指令最低两位都为 0,去除一个符号位，即为2^25)
        if abs(ptrFrom - ptrTo) >= 32 * 1024 * 1024:
            raise Exception("Out of Jump range (|{} - {}| = {} > {})".format(hex(ptrFrom), hex(ptrTo),
                                                                             hex(abs(ptrFrom - ptrTo)),
                                                                             hex(32 * 1024 * 1024)))

    @staticmethod
    def getGotByName(name):
        if name is not None:
            return gotMap.get(str(name))

    @staticmethod
    def recordSymbol(name, ptr):
        functionsMap.setdefault(name, ptr)
        print("[*] recordSym ---> {}\t{}".format(str(name).ljust(15, " "), hex(ptr)))
