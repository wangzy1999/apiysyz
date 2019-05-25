#!/usr/bin/env python
# coding: utf-8


import logging
import datetime

save_time = datetime.datetime.now().strftime('%Y-%m-%d')
logfile = save_time + ".log"

logger = logging.getLogger()
fh = logging.FileHandler(logfile, mode='a')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
fh.setFormatter(formatter)

def save_log(mode, msg):
    if mode == 'INFO' :
        logger.info(msg)
    if mode == 'DEBUG':
        logger.debug(msg)
