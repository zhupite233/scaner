#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

plugin_info = {
        "name": "Nodejs Debugger 远程代码执行漏洞",
        "info": "Nodejs V8 Debugger 调试接口可被外部访问，造成远程命令执行",
        "level": "高危",
        "type": "命令执行",
        "author": "neargle",
        "keyword": "banner:V8-Version",
        "source": 1
    }


