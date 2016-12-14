import logging.config
import os


config = {
    'version': 1,
    'formatters': {
        'default': {
            'format': '%(name)s [%(levelname)s] %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
            'level': 'DEBUG'
        }
    },
    'loggers': {
        'ags': {
            'handlers': ['console'],
            'level': 'DEBUG'
        }
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    }
}

if 'AGS_CLIENT_LOG_PATH' in os.environ:
    config['handlers']['file'] = {
        'class': 'logging.FileHandler',
        'formatter': 'default',
        'level': 'DEBUG',
        'filename': os.environ['AGS_CLIENT_LOG_PATH']
    }
    config['loggers']['ags']['handlers'].append('file')
    config['root']['handlers'].append('file')


def get_logger(name):
    logging.config.dictConfig(config)
    return logging.getLogger(name)
