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

functionsMap = {}


class Jumper:

    def __init__(self, filePath, ARCH=ARCH_ARM):

        self.filePath = filePath
        self.fileName = os.path.basename(filePath)
        self.fileDIR = os.path.abspath(filePath)
        self.lf = lief.parse(filePath)

        self.currentPC = 0
        self.currentPtr = functionsMap.get("GLOBAL_TABLE")
        self.currentStr = functionsMap.get("STR_TABLE")
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
        print("\nCurrent Needed Libraries : ")
        for name in self.lf.libraries:
            print("\t[*] " + name)
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

    def fixCode(self, insList):
        # TODO 修复pc相关指令
        return insList

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

    def patchASM(self, code="nop"):
        self.patchList(self.ks.asm(code)[0])

    def saveEnv(self):
        self.patchASM("push {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")
        self.patchASM("MRS R10, CPSR")
        self.patchASM("STMFD SP!, {R10}")

    def restoreEnv(self):
        self.patchASM("LDMFD SP!, {R10}")
        self.patchASM("MSR CPSR, R10")
        self.patchASM("pop {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}")

    def restoreCode(self, codeIndex=0):
        self.patchList(self.fixCode(self._codeContainer[codeIndex]))

    def save(self, name=None):
        # 保存在传入so的目录下，未填写名称则默认在原名称后面添加一个N
        if name is None:
            oldNameSp = self.fileName.split(".")
            newName = oldNameSp[0] + "N." + oldNameSp[1]
            path = self.fileDIR.replace(self.fileName, newName)
        else:
            path = os.path.dirname(self.filePath) + "/" + name
        self.lf.write(path)
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

        def JMP_B():
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 1
            self.patchASM("B #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))  # B/BL 本就是从当前位置算起
            if showLog:
                print('\n[*] Patch Code TYPE : JMP_B')
                tmpPC = self.currentPC - 4
                print("\t" + hex(tmpPC) + " " + self.getAsmFromList(self._codeContainer[codeIndex])[0]
                      + "\t--->\t" + self.getAsmFromAddress(tmpPC)[0])

        def JMP_BL():
            SaveCode()
            self._returnAddr = self.currentPC + self._pSize * 1
            self.patchASM("BL #{}".format(self.calOffset(self.currentPC - 4 * 2, toAddress)))
            if showLog:
                print('\n[*] Patch Code TYPE : JMP_BL')
                tmpPC = self.currentPC - 4
                print("\t" + hex(tmpPC) + " " + self.getAsmFromList(self._codeContainer[codeIndex])[0]
                      + "\t--->\t" + self.getAsmFromAddress(tmpPC)[0])

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

        def JMP_REL():
            self.patchASM("LDR {}, [PC,#0xC]".format(reg))
            self.patchASM("ADD {}, PC, {}".format(reg, reg))
            self.patchASM("LDR {}, [{}]".format(reg, reg))
            self.patchASM("BLX {}".format(reg))
            self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
            self.patchList(self.calOffsetToList(self.currentPC - 8, toAddress, 0))

        switch = {'LDR': JMP_LDA,
                  'REL': JMP_REL,
                  'BL': JMP_BL,
                  'B': JMP_B}
        switch.get(jmpType, JMP_B)()
        if resetPC:
            self.currentPC = toAddress

    def loadToReg(self, pData, reg="R0"):
        self.patchASM("LDR {}, [PC,#4]".format(reg))
        self.patchASM("ADD {}, PC, {}".format(reg, reg))
        self.jumpTo(self.currentPC + self._pSize * 2, jmpType="B", resetPC=False)
        self.patchList(self.calOffsetToList(self.currentPC - 4, pData, 0))

    def addPtr(self, mPtr):
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
        return tmpAddr

    def getStr(self, mStr):
        # 查找已有字符串的情况，不再走添加流程
        for itemC in self.mapStr.items():
            if itemC[1] == mStr:
                print("[*] Get string at " + str(hex(itemC[0])) + "\t"+mStr)
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
        tmpAddr = self.currentStr - self._pSize
        # 存入String的值
        self.patchList(listStr)
        # 记录在在字典中 mapStr
        self.mapStr.setdefault(tmpAddr, mStr)
        # 修改后指针加一赋值给 AsmCommon 中的 currentStr（下次使用）
        self.currentStr = self.currentPC
        # 恢复修改后的jumper中的 currentPC
        self.currentPC = self._lastPC
        # 保存 string 到 GLOBAL_TABLE
        self.addPtr(self.currentStr - listStr.__len__())
        print("[*] Create string at "+str(hex(tmpAddr)) + "\t"+mStr)
        return tmpAddr

    def getAddrByExpName(self, expName):
        return self.lf.get_symbol(expName).value

    def getRelocation(self, expName):
        return self.lf.get_relocation(expName).address

    # 好像不需要动sp，直接往下写也是可以的，自己记住写的数据在哪里就行了
    def subSp(self, num=0):
        self.patchASM("SUB SP, SP, #{}".format(self._pSize * num))
        self._AllocSpSize = num

    def restoreSp(self):
        self.patchASM("ADD SP, SP, #{}".format(self._AllocSpSize))

    # 调用 addHook 之后 currentPC 指向了我们写代码的位置，写完了记得 “bl lr" 即可
    def addHook(self, mPtr):
        self.jumpTo(self.currentTramp, mPtr, codeIndex=0, jmpType="LDR", reg="R12", resetPC=True, resetBackPC=True)
        self.saveEnv()
        self.jumpTo(self.currentCodes, jmpType="BL", resetPC=False)
        self.restoreEnv()
        self.restoreCode(codeIndex=0)
        self.jumpTo(self._jumpBackPC, fromAddress=self.currentPC, jmpType="LDR", reg="LR", resetPC=False)
        self.currentTramp = self.currentPC
        self.currentPC = self.currentCodes
        self.patchASM("STMFD SP!, {LR}")

    def endHook(self):
        self.patchASM("LDMFD SP!, {PC}")

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

    def android_log_print(self, prio=3, tag="ZZZ", msg="Called", reg0="R1", reg1="R2", reg2="R3"):
        self.patchASM("MOV R0, #{}".format(prio))
        self.loadToReg(self.getStr(tag), reg=reg0)
        self.loadToReg(self.getStr(msg), reg=reg1)
        self.jumpTo(self.getRelocation("__android_log_print"), jmpType="REL", reg=reg2, resetPC=False)


class MergeUtils:
    # 第二个so 合并到第一个so
    def __init__(self, path1, path2):
        self.path1 = path1
        self.path2 = path2
        self.savePath = os.path.dirname(self.path1) + "/libil2cppN.so"
        self.lf_1 = lief.parse(path1)
        self.lf_2 = lief.parse(path2)
        self.vAddr = None
        self.section = None

    def mergeSecs(self):
        self.vAddr = -1
        return {".text": self.mergeSection(".text"),
                ".rodata": self.mergeSection(".rodata"),
                ".data": self.mergeSection(".data")}

    # 合并整个段
    def mergeSeg(self):
        # self.lf_1.add_exported_function(0x5465D8, "SettingsMenuIn")
        self.vAddr = self.lf_1.add(self.lf_2.segments[1]).virtual_address
        print("[*] mergeSeg => "+self.lf_2.segments[1] + " => "+self.vAddr)
        self.save()

    # 合并指定节
    def mergeSection(self, section=".text"):
        # 添加了导出函数就会崩溃
        # self.lf_1.add_exported_function(0x5465D8, "SettingsMenuIn")
        self.section = section
        self.lf_1.add(self.lf_2.get_section(section))
        # 先保存一下再打开重新回去vAddr
        self.lf_1 = lief.parse(self.save())
        self.vAddr = self.lf_1.get_section(section).virtual_address
        print("[*] mergeSection => " + section + " => "+str(hex(self.vAddr)))

    def fixSym(self):
        pass

    def fixInit(self):
        pass

    def getSym1(self, symName):
        return self.lf_1.get_symbol(symName).value

    def getSym2(self, symName):
        if self.section is None:
            return self.vAddr + self.lf_2.get_symbol(symName).value
        else:
            ret = self.vAddr + (
                    self.lf_2.get_symbol(symName).value - self.lf_2.get_section(self.section).virtual_address)
            return ret

    def addExpFunc(self, mPtr, symName):
        self.lf_1.add_exported_function(mPtr, symName)
        return mPtr

    def save(self):
        self.lf_1.write(self.savePath)
        return self.savePath


if __name__ == '__main__':
    # so 合并以及导出我们需要用到地址
    ins = MergeUtils(r"C:\Users\pc\PycharmProjects\SoInject\files\libil2cpp.so",
                     r"C:\Users\pc\AndroidStudioProjects\liefInject\app\release\libinject.so")
    ins.mergeSection(".inject")
    # ins.mergeSeg()

    functionsMap.setdefault("GLOBAL_TABLE", ins.getSym2("GLOBAL_TABLE"))
    functionsMap.setdefault("STR_TABLE", ins.getSym2("STR_TABLE"))
    functionsMap.setdefault("trampolines", ins.getSym2("trampolines"))
    functionsMap.setdefault("textCodes", ins.getSym2("textCodes"))

    functionsMap.setdefault("SettingsMenuIn", 0x5475D8)

    print("\n")
    for item in functionsMap.items():
        print("[*] "+item[0] + " ---> " + hex(item[1]))

    newSoPath = ins.save()

    ins = Jumper(newSoPath)
    ins.addPtr(100)
    ins.addPtr(200)
    ins.addPtr(300)
    ins.getStr("this is a test string!")
    ins.getStr("测试文本文件")

    ins.addHook(functionsMap.get("SettingsMenuIn"))
    ins.android_log_print(msg="called this function")
    ins.endHook()

    ins.save()
