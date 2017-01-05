import logging
import os


def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('{name} {levelname} {message}', style='{')
    handlers = [logging.StreamHandler()]

    if 'AGS_CLIENT_LOG_PATH' in os.environ:
        handlers.append(
            logging.FileHandler(filename=os.environ['AGS_CLIENT_LOG_PATH']))

    for handler in handlers:
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
