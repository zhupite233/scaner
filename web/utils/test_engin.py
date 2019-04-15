# --*-- coding: utf-8 --*--
import sys
# sys.path.insert(0, 'E:\\devProject\\scaner\\app\\engine')
from engine.WebScanEngine import WebScanEngine
# from app.engine.WebScanEngine import WebScanEngine


def run_engine(args):
    print 'run_engine', args

    web_scan_engine = WebScanEngine(args[0], args[1])
    web_scan_engine.run()


if __name__ == '__main__':
    run_engine([1178, 'restart'])