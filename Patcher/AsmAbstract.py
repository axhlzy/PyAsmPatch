from abc import abstractmethod, ABCMeta

from typing import List


class AsmAbstract(metaclass=ABCMeta):

    @abstractmethod
    def save(self, name: str = ''):
        pass

    @abstractmethod
    def resetPC(self, pc: int):
        pass

    @abstractmethod
    def addBP(self, mPtr: int = None):
        pass

    @abstractmethod
    def asmToList(self, asm: str = 'nop') -> List[bytes]:
        pass

    @abstractmethod
    def listToAsm(self, mList: list) -> str:
        pass

    @abstractmethod
    def patchASM(self, asm: str = "nop", labName: str = None):
        pass

    @abstractmethod
    def preLabel(self, labName: str = None):
        """
        用来记录标签的位置
        :param labName: 标签名
        :return: None
        """
        pass

    @abstractmethod
    def patchList(self, mList: List[bytes]):
        """
        修改汇编指令，参数为 : list of bytes
        :param mList: list of bytes
        :return: None
        """
        pass
