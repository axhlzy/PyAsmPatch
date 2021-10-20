import logging
import sys

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
