ARCH_ARM = 4
ARCH_ARM64 = 8

configSize = {"GLOBAL_TABLE": 2000, "STR_TABLE": 2000, "GOT_TABLE": 2000, "trampolines": 2000, "textCodes": 5000,
              "GOT_TABLE_fill": 500, "mProtect_size": 1024 * 40, "offset": 0}
hookedFunctions = {}
functionsMap = {}
gotMap = {}
