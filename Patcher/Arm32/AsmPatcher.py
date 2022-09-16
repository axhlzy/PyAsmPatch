import os

from Patcher.BaseClass import BaseClass


class AsmPatcher(BaseClass):
    def __init__(self, path):
        BaseClass.__init__(self, path)

    def addBP(self, mPtr=None):
        if mPtr is not None:
            self.resetPC(self._currentPC)
        # FE FF FF EA    死循环
        self.patchASM("b #0")
