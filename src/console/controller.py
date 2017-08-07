from core.scanner import GitScanner


def hcs_parser_ctl(token: str, targets: str, proxy: str, out: list, server: str, regex: str, filters: str = None):
    """
   Controller for hcs parser.
   :param token:
   :param targets:
   :param proxy:
   :param out:
   :param server:
   :param regex:
   :return:
   """
    git = GitScanner(token=token, targets=targets, proxy=proxy, server=server, filters=filters, regex=regex)
    git.scan(out.strip().upper().split(','))
