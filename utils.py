import shodan
import time
import sys
import threading


global positive_answers
global negative_answers
positive_answers = ['y', 'ye', 'yes']
negative_answers = ['n', 'no', 'nop']


class HelpMessage:
    query_help = "General search query (e.g: \"Akamai server\")"
    host_help = "Specify hostname (e.g: 56.65.56.65)"
    port_help = "Specify port (e.g: 443)"
    city_help = "Specify city (e.g: \"New York\")"
    country_help = "Specify country (e.g: \"United States\")"
    os_help = "Specify operating system (e.g: \"windows 2003\")"
    net_help = "Specify subnet (e.g: \"216.0.0.0/16\")"
    before_help = "Specify newest date (e.g: \"05/12/1995\", \"05-12-95\")"
    after_help = "Specify oldest date (e.g: \"05/12/1995\", \"05-12-95\")"
    key_help = "Your Shodan API key (REQUIRED)"

    def __init__(self):
        pass


# Victor Moyseenko's spinner: http://stackoverflow.com/a/39504463
class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/-\\': yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        self.busy = False
        time.sleep(self.delay)


class CustomParser:
    # 'key' = '-1' is a flag to prompt the user for a key.
    def handle_login(self, key):
        if key is -1:
            key = raw_input("Enter your Shodan API key: ")
        try:
            self.api = shodan.Shodan(key)
            self.api.info() # testing if successfully logged-in
            print 'Logged-in to Shodan.'
        except shodan.APIError, e:
            print 'Encountered error: %s\nTry again.' % e
            CustomParser.handle_login(self, -1)

    def handle_arguments(self, args):
        args.query = raw_input('Enter search query (ENTER for wildcard): ')
        filters_answer = raw_input('Apply optional search filters? (yes/no): ')
        if any(filters_answer.lower() == answer for answer in positive_answers):
            padding = ': '
            print 'Press ENTER to skip filter.'
            args.host = raw_input(HelpMessage.host_help + padding)
            args.port = raw_input(HelpMessage.port_help + padding)
            args.city = raw_input(HelpMessage.city_help + padding)
            args.country = raw_input(HelpMessage.country_help + padding)
            args.net = raw_input(HelpMessage.net_help + padding)
            args.os = raw_input(HelpMessage.os_help + padding)
            args.before = raw_input(HelpMessage.before_help + padding)
            args.after = raw_input(HelpMessage.after_help + padding)

    def offer_query_discovery(self):
        if self.api is None:
            return
        discovery_answer = raw_input('Discover popular user-shared search queries? (yes/no): ')
        results = None
        if any(discovery_answer.lower() == answer for answer in positive_answers):
            results = self.api.queries(page=1, sort='votes', order='desc')
        return results

    def __init__(self, args):
        self.api = None
        if args.key is None:
            CustomParser.handle_login(self, -1)
        else:
            CustomParser.handle_login(self, args.key)


def quote_string(in_str):
    if in_str is not None and in_str != '':
        if in_str[0] == '\"':  # Already quoted.
            return in_str
        else:
            return '\"'+in_str+'\"'
    else:
        return '\"\"'       # Safety layer.


def check_int(str):
    try:
        val = int(str)
        return val
    except ValueError:
        return -1