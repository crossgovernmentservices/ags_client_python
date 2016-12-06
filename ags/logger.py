import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(sh)

fileLoggingSet = False


def set_log_path(log_path):
    global fileLoggingSet
    if log_path and fileLoggingSet == False:
        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s - AGS Client - %(levelname)s - %(message)s'))
        logger.addHandler(fh)
        fileLoggingSet = True
