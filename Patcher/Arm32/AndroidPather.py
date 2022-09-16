from Patcher.Arm32.AsmPatcher import AsmPatcher


class AndroidPatcher(AsmPatcher):

    def __init__(self, path):
        AsmPatcher.__init__(self, path)
