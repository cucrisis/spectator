import json
import time
import logging


class Reporter(object):
    OPTIONS = ['JSON', 'SIMPLE', 'NOTIFIER']
    CSV_FILE_KEYS = ['Q']

    def __init__(self, reporting_options, git=None):
        self.report_file = "observer_report_%s" % str(time.strftime("%c")).replace(' ','-')
        self.reporting_options = reporting_options
        self.results = list()
        self.git = git

    def write_to_file(self, format_str: str, finding):
        """
        Write to file
        :return:
        """
        if format_str == 'JSON':
            with open(self.report_file + ".json",'a') as report:
                report.write(json.dumps(finding))

    def report(self, finding):
        self.results.append(finding)

        if 'SIMPLE' in self.reporting_options:
            print("[+] "+finding['title'] + " | " + finding['reference']+Reporter.get_finding_content(finding))
        if 'JSON' in self.reporting_options:
            self.write_to_file('JSON', finding)
        if 'NOTIFIER' in self.reporting_options:
            GitNotifier.report(self.git, finding)

    @staticmethod
    def get_finding_content(finding):
        # Extract vulnerable snippets
        vulnerable_segments = ''
        for vul_instance in finding['vuln']:
            vulnerable_segments += "\n[...snip...]\n%s\n[...snip...]\n" % vul_instance['fragment']

        return vulnerable_segments

    def get_results(self):
        return json.dumps(self.results)


class GitNotifier(object):
    FINDING_LABELS = ['bug', 'spectator']

    @staticmethod
    def get_issue_content(finding):
        body = "**Overview:**\n%s\n\n**Remediation:**\n%s\n\n**File:**\n%s \n\n\n**Vulnerable segment:**\n%s\n\n\n"

        # Extract vulnerable snippets
        vulnerable_segments = ''
        for vul_instance in finding['vuln']:
            vulnerable_segments += "```\n[...snip...]\n%s\n[...snip...]\n```\n" % vul_instance['fragment']

        return body % (finding['overview'], finding['remediation'], finding['reference'], vulnerable_segments)

    @staticmethod
    def report(client, finding):
        """
        Notify as an issue in repo.
        :return:
        """
        logging.info('create issues for [%s] - %s' % (finding['owner']['title'],finding['repo']))

        report = 'Finding %s | Stake holder repo: %s  owner: %s' % \
                 (
                     finding['title'],
                     finding['repo'],
                     finding['owner']['type'] + "-" + finding['owner']['title']
                 )

        repo = client.repository(owner=finding['owner']['title'], repository=finding['repo'])
        repo.create_issue(finding['title'],
                          labels=GitNotifier.FINDING_LABELS,
                          body=GitNotifier.get_issue_content(finding))