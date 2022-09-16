import argparse
import os
from Patcher.Arm32.UnityPatcher import UnityPatcher

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Need input a il2cpp file path')
    parser.add_argument('-p', '--path', help='add a path to parse', required=True, type=str, nargs=1)
    parser.add_help = True
    args = parser.parse_args()
    path = args.path[0]
    parentDir = os.path.dirname(path)

    patcher = UnityPatcher(path)

    patcher.save()
