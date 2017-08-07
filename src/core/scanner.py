import os
import json
import time
import logging
import requests
import threading
import github3 as github

from .reporter import Reporter

# SSL WARNING Disable warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class GitScanner(object):
    TARGET_TYPES = ['org', 'repo', 'user']

    DEFAULT_USER_AGENT = 'SPECTATOR'
    DEFAULT_ISSUE_LABELS = ['bug', 'observer']
    DEFAULT_TARGET_SERVER = 'github.organization.com'

    def __init__(self,
                 token: str, targets: str, proxy: str, regex: str, filters: str = None, server: str='https://%s' % DEFAULT_TARGET_SERVER):
        if not token:
            raise ValueError('token must be set')
        if not regex:
            raise ValueError('regex file must be set')
        if not os.path.exists(regex):
            raise ValueError('regex file doesnt exist in path %s' % regex)

        # Set variables
        self.token = token
        self.proxy = proxy
        self.regex = regex
        self.server = server
        self.targets = targets
        self.filters = filters.strip().split(",") if filters else None

        # Target & Regex list.
        self.targets_list = GitScanner.get_targets_list(self.targets)
        self.regex_list = GitScanner.get_regex_list(self.regex, self.filters)

        # Set env proxy if provided
        if proxy:
            os.environ['HTTP_PROXY'] = proxy
            os.environ['HTTPS_PROXY'] = proxy

        # Create Enterprise Git client
        self.git_client = github.GitHubEnterprise(url=server, token=token, verify=False)

        # output to file & console
        logging.info('[+] GitScanner')
        logging.info('[+] GitScanner targets ->  %d targets ' % len(self.targets_list))
        logging.info('[+] GitScanner regex   ->  %d regex\'s' % len(self.regex_list))
        logging.info('[+] GitScanner server  ->  %s' % self.server)
        logging.info('[+] GitScanner proxy   ->  %s' % self.proxy)

    def scan(self, reporting_options):
        """
        Start scan
        :return:
        """
        logging.info('[+] GitScanner - Start scanning')
        reporter = Reporter(reporting_options=reporting_options, git= self.git_client)

        # Create Threads
        logging.info('[+] GitScanner - Start scanning / Create Threads')
        regex_threads_list = list()
        for regex in self.regex_list:
            for pattern in regex['patterns']:
                regex_thread = threading.Thread(
                    target=GitScanner.scan_regex, args=(reporter, regex, self.targets_list,pattern,self.git_client,)
                )
                regex_threads_list.append(regex_thread)

        logging.info('[+] GitScanner - Start scanning / Threads [%d] created' % len(regex_threads_list))
        logging.info('[+] GitScanner - Start scanning / Running')

        # Start Threads
        [thread.start() for thread in regex_threads_list]

        # Monitor Threads
        while not list(filter(lambda thread: thread.is_alive(), regex_threads_list)):
            print('scanning...'); time.sleep(8)

        # Generate Report
        logging.info("[+] GitScanner - Scanning Completed")
        logging.info("[+] GitScanner - Generate Report Statistics")

    @staticmethod
    def scan_regex(reporter, regex, targets_list, pattern, git):
        logging.info('[+] Checking for %s' % regex['title'])

        # Execute search
        search_request = GitScanner.get_search_query(regex, targets_list, pattern)

        if search_request:
            logging.info('[+] Using Query [%s]' % search_request)
            regex_entry_points = git.search_code(query=search_request, text_match=True)

            # Iterate over result & report findings
            for regex_entry_point in regex_entry_points:
                # Create finding structure
                regex_entry_point_result = {
                    'Q': search_request,
                    'reference': regex_entry_point.html_url,
                    'file': regex_entry_point.name,
                    'score': regex_entry_point.score,
                    'sha': regex_entry_point.sha,
                    'repo': regex_entry_point.repository.name,
                    'vuln': regex_entry_point.text_matches,
                    'title': regex['title'],
                    'overview': regex['overview'],
                    'remediation': regex['remediation'],
                    'owner': {
                        'title': regex_entry_point.repository.owner.__str__(),
                        'type': 'org' if isinstance(
                            regex_entry_point.repository, github.orgs.Organization
                        ) else 'user'
                    }
                }
                # Report Finding
                reporter.report(regex_entry_point_result)

    @staticmethod
    def get_regex_list(regex: str, filters:list())-> list:
        regex_result_list = []
        regex_list = json.loads(open(regex).read())
        keys = ('patterns', 'title', 'overview', 'remediation', 'locations','key')

        # Check for structure
        for regex in regex_list:
            regex_missing_keys = []
            for key in keys:
                if key not in regex.keys():
                    regex_missing_keys.append(key)

            if regex_missing_keys:
                logging.warning('[-] regex: %s misses the following essential keys  %s -> Ignoring regex ' % (
                    regex['title'], regex_missing_keys
                ))
            else:
                if filters:
                    if regex['key'] in filters:
                        regex_result_list.append(regex)
                else:
                    regex_result_list.append(regex)
        return regex_result_list

    @staticmethod
    def get_targets_list(targets: str) -> list:
        """
        Support for multiple targets format.
        file: with entries type;target
        str: with entries type;target, type;target, type;target ...
        str: type;target
        :param targets:
        :return:
        """

        def process_line(line: str) -> tuple:
            """
            split line using `;` delimiter & check if target_type its in GitScanner.TARGET_TYPES.
            :param line:
            :return:
            """
            result = None
            if ';' in line:
                target_info = line.split(';')
                target_type, target = target_info[0], target_info[1]
                if target_type in GitScanner.TARGET_TYPES:
                    result = (target_type, target)
                else:
                    logging.warning('[-] target type not in list, ignoring target %s;%s', target[0], target)
            return result

        targets_result = list()

        if targets:

            # if its a  file with lines in format type;target
            if os.path.exists(targets):
                for line in open(targets, 'r').readlines():
                    target = process_line(line)
                    if target:
                        logging.info('[+]  target %s;%s', target[0], target[1])
                        targets_result.append(target)

            # if its a str line multiple entries type;target,type;target
            if ";" in targets and "," in targets:
                for line in targets.replace(' ', '').split(","):
                    target = process_line(line)
                    if target:
                        targets_result.append(target)
                        logging.info('[+] target %s;%s', target[0], target[1])

            # if its a str single entry
            if ";" in targets and ',' not in targets:
                target = process_line(targets.replace(' ', ''))
                if target:
                    targets_result.append(target)
                    logging.info('[+]  target %s;%s', target[0], target[1])

        return targets_result

    @staticmethod
    def get_search_query(regex, targets: list, pattern: str) -> str:
        """
        Return query if regex is formatted correctly otherwise return None
        Reference: https://help.github.com/articles/searching-code/

        :param regex:
        :param targets:
        :param pattern:
        :return:
        """
        # Check entry format
        # Include pattern
        search_query = '"%s"' % pattern

        # Pattern
        # In: file, path
        search_query = search_query + ' in:%s ' % ', '.join(regex['locations']) \
            if 'locations' in regex.keys() and len(regex['locations']) > 0 else search_query

        # extension:java, c, xml ...etc
        search_query = search_query + ' extension:%s ' % ', '.join(regex['extensions']) \
            if 'extensions' in regex.keys() and len(', '.join(regex['extensions'])) > 0 else search_query

        # language:java, python, c# ...etc
        search_query = search_query + ' language:%s ' % ', '.join(regex['languages']) \
            if 'languages' in regex.keys() and len(','.join(regex['languages'])) > 0 else search_query

        # path:src, config, public, private
        search_query = search_query + ' path:%s ' % ', '.join(regex['paths']) \
            if 'paths' in regex.keys() and len(','.join(regex['paths'])) > 0 else search_query

        # Targets scope. if target list is empty will query everyone.
        targets_scope_query = ''
        if targets:
            targets_scope_store = {'org': [], 'user': [], 'repo': []}
            targets_passed_types = []
            for t_type, target in targets:
                if t_type in targets_scope_store.keys():
                    targets_scope_store[t_type].append(target)
                    targets_passed_types.append(t_type)

            for key in targets_passed_types:
                targets_scope_query = targets_scope_query + str(" %s:%s" % (key, ', '.join(targets_scope_store[key])))
        return str(search_query + targets_scope_query).rstrip()







