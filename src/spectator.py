import os
import logging


from console import parser

# Setup workspace
SPEC_HCS_ACCESS_TOKEN = os.getenv('SPECTATOR_HCS_TOKEN', '')
SPEC_OUTPUT_FILE_PATH = os.getenv('SPECTATOR_LOG', '../config/spectator.log')
SPEC_REGEX_FILE_PATH = os.getenv('SPECTATOR_CONFIG', '../config/spectator.common.regex.json')

# Setup logger
logging.basicConfig(filename=SPEC_OUTPUT_FILE_PATH, level=logging.INFO)


class Observer():
    @staticmethod
    def run_console():
        parser.parse()


if __name__ == '__main__':
    Observer.run_console()