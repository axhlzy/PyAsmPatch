import lief


class Utils:

    @staticmethod
    def allocCodeSeg(segName='.n_code', segLen=0x2000):
        localSeg = Utils.__alloc(segName, segLen)
        localSeg += lief.ELF.SECTION_FLAGS.EXECINSTR
        return localSeg

    @staticmethod
    def allocDataSeg(segName='.n_data', segLen=0x2000):
        localSeg = Utils.__alloc(segName, segLen)
        localSeg += lief.ELF.SECTION_FLAGS.WRITE
        localSeg += lief.ELF.SECTION_FLAGS.ALLOC
        return localSeg

    @staticmethod
    def __alloc(segName='.n_data', segLen=0x2000):
        localSeg = lief.ELF.Section(segName)
        localSeg.alignment = 0x1000
        for i in range(0, segLen):
            localSeg.content += bytes([0x0])
        return localSeg

    @staticmethod
    def checkJmpRange(ptrFrom, ptrTo):
        # B指令和BL指令最大跳转距离是 ±32M (bits[23:0]是立即数空间,指令最低两位都为 0,去除一个符号位，即为2^25)
        if abs(ptrFrom - ptrTo) >= 32 * 1024 * 1024:
            raise Exception("Out of Jump range (|{} - {}| = {} > {})".format(hex(ptrFrom), hex(ptrTo),
                                                                             hex(abs(ptrFrom - ptrTo)),
                                                                             hex(32 * 1024 * 1024)))
