import logging
import argparse

from observer import OBS_OUTPUT_FILE_PATH
from observer import OBS_REGEX_FILE_PATH
from observer import OBS_HCS_ACCESS_TOKEN

from .controller import hcs_parser_ctl


def parse_exec(parser: argparse.ArgumentParser):
    """
     parse known args, execute func of the parser.
    :param parser:
    :return:
    """
    # Parse
    args, unknown_args = parser.parse_known_args()

    if args:
        args = vars(args)
        if 'func' in args.keys():
            args_func = args.pop('func')
            args_func(**args)
    else:
        parser.print_help()

    if unknown_args:
        print('This args are not supported: %s', unknown_args)


def parse():
    """
    Console parser.
    :return:
    """

    # Create parser
    parser = argparse.ArgumentParser(description='Spectator')
    plugins_parser = parser.add_subparsers(title='core', description='Plugins')

    # Secrets scanner parser
    scs_parser = plugins_parser.add_parser('scs', help='Source Code Scanner')
    scs_parser.add_argument('-t', type=str, dest='token', help='Access token', default=OBS_HCS_ACCESS_TOKEN)
    scs_parser.add_argument('-r', type=str, dest='regex', help='Regex file to be used', default=OBS_REGEX_FILE_PATH)
    scs_parser.add_argument('-x', type=str, dest='targets',
                            help='Targets. can be file, or single line. in format [org|user|repo];target')
    scs_parser.add_argument('-s', type=str, dest='server', help='Target enterprise server')
    scs_parser.add_argument('-p', type=str, dest='proxy', help='Proxy to tunnel the connection through')
    scs_parser.add_argument('-f', type=str, dest='filters', help='run only the following regex. provide in str,str,str')
    scs_parser.add_argument('-o', type=str, dest='out', help='Output type [JSON, SIMPLE, NOTIFIER]', default='SIMPLE')

    scs_parser.set_defaults(func=hcs_parser_ctl)

    # Parse
    parse_exec(parser)


