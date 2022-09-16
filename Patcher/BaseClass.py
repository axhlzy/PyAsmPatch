import os
from typing import List

import lief
import keystone
import capstone

from abc import abstractmethod
from Patcher.AsmAbstract import AsmAbstract
from utils.preAsm import Utils


class BaseClass(AsmAbstract):

    def __init__(self, path):
        AsmAbstract.__init__(self)
        self.f_path = path
        self.f_dir = os.path.dirname(path)

        # 当前pc（记录下一个待修改的地址）
        self._currentPC = 0
        self._off_code: int = 0
        self._off_data: int = 0

        # 用来记录标签的位置（）
        self._preLabelFuncMap = [{}, {}]

        self.lf = lief.parse(path)
        if self.lf is None:
            raise Exception('lief parse failed')

        self._ARCH = self.lf.header.machine_type

        # 判断 so 类型
        if self._ARCH == lief.ELF.ARCH.ARM:
            self.cs: capstone = capstone.Cs(
                capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            self.ks: keystone = keystone.Ks(
                keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        elif self._ARCH == lief.ELF.ARCH.AARCH64:
            # raise Exception('Not support arch')
            self.cs: capstone = capstone.Cs(
                capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            self.ks: keystone = keystone.Ks(
                keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        else:
            raise Exception('Not support arch')

        # 添加段
        self.seg_code: lief.ELF.Section = self.lf.add(Utils.allocCodeSeg())
        self.seg_data: lief.ELF.Section = self.lf.add(Utils.allocDataSeg())

    def resetPC(self, pc: int):
        self._currentPC = pc

    def save(self, name: str = ''):
        if name != '':
            newname = (name if name.endswith('.so') else name + '.so')
        else:
            newname = 'new_' + os.path.basename(self.f_path)
        newPath = os.path.join(os.path.dirname(self.f_path), newname)
        self.lf.write(newPath)
        print('\nWrite to {}'.format(newPath))

    def asmToList(self, asm: str = 'nop'):
        return self.ks.asm(asm)[0]

    def listToAsm(self, mList: List[bytes]):
        return self.cs.disasm(mList, self._currentPC).__next__()

    def patchASM(self, asm: str = 'nop', labName: str = None):
        self.preLabel(labName)
        self.patchList(self.asmToList(asm))

    def preLabel(self, labName: str = None):
        if labName is not None:
            self._preLabelFuncMap[0].setdefault(labName, self._currentPC)

    def patchList(self, mList: List[bytes]):
        self.lf.patch_address(self._currentPC, mList)
        self._currentPC += mList.__len__()

    @abstractmethod
    def addBP(self, mPtr=None):
        pass
