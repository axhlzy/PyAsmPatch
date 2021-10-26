#
#  @Author      lzy <axhlzy@live.cn>
#  @HomePage    https://github.com/axhlzy
#  @CreatedTime 2021/09/30 18:42
#  @UpdateTime  2021/10/20 11:56
#  @Des         Use lief to merge two so files
#

import os
import lief

from Config import configSize, functionsMap


class MergeUtils:
    def __init__(self, path1, path2=r"C:\Users\pc\AndroidStudioProjects\liefInject\app\release\libinject.so"):
        self.path1 = path1
        self.path2 = path2
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

        configSize["offset"] = self.text.virtual_address - tempOff
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

    @staticmethod
    def recordSymbol(name, ptr, fix=True):
        if str(name) in ("GLOBAL_TABLE", "STR_TABLE", "trampolines", "textCodes", "GOT_TABLE") or not fix:
            functionsMap.setdefault(name, ptr)
            print("[*] recordSym ---> {}\t{}".format(str(name).ljust(15, " "), hex(ptr)))
        else:
            functionsMap.setdefault(name, ptr + configSize["offset"])
            print("[*] recordSym ---> {}\t{} ---> {}".format(str(name).ljust(25, " "), hex(ptr).ljust(10, " "),
                                                             hex(ptr + configSize["offset"])))

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
