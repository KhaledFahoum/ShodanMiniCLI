import shodan
import sys
import argparse
import utils
from utils import HelpMessage, quote_string, check_int

# Refer to https://www.exploit-db.com/docs/33859.pdf for Shodan API info

column_width = 30
separator_width = 60
batch_size = -1         # '-1' = infinite
index = -1              # Number of currently displayed search results.
horizontal_bar = '=' * column_width * 6
small_horizontal_bar = '='*50


# Builds a search query from the provided arguments.
def build_query(args):
    final_query = quote_string(args.query)
    # 'args.query' could be a blank string, which is valid for filter-only search.
    if args.host != '' and args.host is not None:
        final_query += ' host:'+quote_string(args.host)
    if args.port != '' and args.port is not None:
        final_query += ' port:'+quote_string(args.port)
    if args.city != '' and args.city is not None:
        final_query += ' city:'+quote_string(args.city)
    if args.country != '' and args.country is not None:
        final_query += ' country:'+quote_string(args.country)
    if args.os != '' and args.os is not None:
        final_query += ' os:'+quote_string(args.os)
    if args.net != '' and args.net is not None:
        final_query += ' net:'+quote_string(args.net)
    if args.before != '' and args.before is not None:
        final_query += ' before:'+quote_string(args.before)
    if args.after != '' and args.after is not None:
        final_query += ' after:'+quote_string(args.after)
    return final_query


def print_discovery_result(result):
    votes = str(result['votes'])
    diff1 = 5 - len(votes)
    tags = ''
    for tag in result['tags']:
        tags+= str(tag)+' '
    print '[VOTES] '+votes+ ' '*diff1+' [TITLE] '+str(result['title'])
    print '[QUERY] '+str(result['query'])
    print '[DESCRIPTION] '+str(result['description'])
    print '[TAGS] '+str(tags)
    print '[TIMESTAMP] '+str(result['timestamp'])
    print horizontal_bar


# Prints a single search result as a record
def print_search_result(result, index):
    max_len = column_width - 2
    ip_port_max_len = 20                    # Based on header sizes.
    domains = str(result['domains'])
    domains = domains[3:len(domains)-2]     # Removing brackets [u' .. ]
    domains = domains[:max_len]
    if 'asn' not in result:
        asn = 'None'
    else:
        asn = str(result['asn'])[:max_len]
    if 'isp' not in result:
        isp = 'None'
    else:
        try:
            isp = str(result['isp'])
        except Exception, e:
            isp = 'None'
    if len(isp) > max_len - 10:
        isp = isp[:max_len-12] + '..'
    else:
        isp = isp[:max_len-8]
    if 'org' not in result:
        organization = 'None'
    else:
        try:
            organization =  str(result['org'])[:max_len]
        except Exception, e:
            organization = 'None'
    ip_str = str(result['ip_str'])[:max_len]
    port_str = str(result['port'])[:max_len]
    diff = ip_port_max_len - len(ip_str) - 5 - 1    # 5 = max port len
    diff2 = 1+7 - len(asn)                            # 7 = max asn len
    diff3 = 6 - len(str(index))
    row = ['[#'+str(index)+']'+' '*diff3+ip_str+' '*diff+':'+port_str,
          organization, domains, asn+' '*diff2+'- '+isp,
           (str(result['location']['city'])+', '+
            str(result['location']['country_name']))[:max_len]]
    print "".join(word.ljust(column_width) for word in row)


def print_search_result_header():
    header = ['#'+' '*19+'IP:PORT', ' '*4+'ORGANIZATION', 'DOMAIN', '    ASN - ISP', 'LOCATION']
    print "".join(word.ljust(column_width) for word in header)


def print_host_result(host):
    ports = ''
    hostnames = ''

    for port in host['ports']:
        ports += str(port)+' '
    for hostname in host['hostnames']:
        hostnames += str(hostname) + ' '
    print horizontal_bar
    print '[IP] '+str(host['ip_str'])+ ' - [HOSTNAMES] '+hostnames
    print '[OPEN PORTS] '+ports+'- [OS] '+str(host['os'])
    print '[ORGANIZATION] '+str(host['org'])
    print '[ISP] '+str(host['isp'])+' - [ASN] '+str(host['asn'])
    print '[LOCATION] '+str(host['country_name'])+' - [LONGITUDE - LATITUDE] '\
                            +str(host['longitude'])+' - '+str(host['latitude'])
    print '\n'+small_horizontal_bar+'Running services:'+small_horizontal_bar+'\n'
    i = 1
    for item in host['data']:
        port = str(item['port'])
        diff1 = 5 - len(port)
        if 'product' in item:
            product = str(item['product'])
        else:
            product = 'None'
        domains = ''
        for domain in item['domains']:
            domains += str(domain)+' '
        hostnames = ''
        for hostname in item['hostnames']:
            hostnames += str(hostname) + ' '
        print '[[SERVICE #'+str(i)+']]'
        print '[IP] '+str(item['ip_str'])+' [PORT] '+port+' '*diff1+\
                                ' [PROTOCOL] '+str(item['transport'])
        print '[DEVICE] '+product
        print '[DOMAINS] '+domains
        print '[HOSTNAMES] '+hostnames
        print '[BANNER]\n'+str(item['data'])
        i+=1
        print small_horizontal_bar


def validate_still_logged_in():
    try:
        api.info()              # Testing if still logged-in
    except shodan.APIError, e:  # Not logged-in.
        sys.exit(1)


'''
    ### ENTRY POINT ###
'''

parser = argparse.ArgumentParser()
parser.add_argument('--key', help = HelpMessage.key_help)
parser.add_argument('--query', help = HelpMessage.query_help)
parser.add_argument('--host', help = HelpMessage.host_help)
parser.add_argument('--port', help = HelpMessage.port_help)
parser.add_argument('--city', help = HelpMessage.city_help)
parser.add_argument('--country', help = HelpMessage.country_help)
parser.add_argument('--os', help = HelpMessage.os_help)
parser.add_argument('--net', help = HelpMessage.net_help)
parser.add_argument('--before', help = HelpMessage.before_help)
parser.add_argument('--after', help = HelpMessage.after_help)
args = parser.parse_args()
custom_parser = utils.CustomParser(args)  # Logging in Shodan.
api = custom_parser.api

'''
    From here on, we're logged-in with the API key
    and 'args' has all the minimum required values. (API key)
'''

spinner = utils.Spinner()
if len(sys.argv) > 4:   # Running in script mode; search and exit.
    query = build_query(args)
    if len(query) < 1 or len(sys.argv) % 2 != 0:
        print 'Usage: python shodanCLI.py --key <your-API-key> [options]\n'
        sys.exit(1)
    index = 0
    try:
        results = api.search(query)
        print 'Searching for: '+query
        print 'Found %s services!' % results['total']
        # Printing all results at once.
        for service in results['matches']:
            print_search_result(service, index)
            index += 1
    except shodan.APIError, e:
        print 'Encountered error: %s\nShodanCLI shutting down.' % e
        sys.exit(1)
    print 'End of results. ShodanCLI shutting down.'
    sys.exit(1)

while(1):               # Running in interactive mode; prompting for args.
    results = custom_parser.offer_query_discovery()
    if results is not None:
        print horizontal_bar
        for query in results['matches']:
            print_discovery_result(query)
    custom_parser.handle_arguments(args)
    query = build_query(args)
    index = 0

    if query == '':
        print 'No query entered. ShodanCLI shutting down.'
        sys.exit(1)

    try:
        results = api.search(query)
        print 'Searching for: '+query
        spinner.start()
        print 'Found %s services!' % results['total']
        spinner.stop()
        print_search_result_header()
        batch_counter = -1        # One-time offset like a noob.

        # Iterating on results.
        for service in results['matches']:
            batch_counter+= 1
            if batch_counter == batch_size:
                more_results_prompt = 'Display more results? (ENTER/no/all): '
                user_input = raw_input(more_results_prompt).lower()
                if any(user_input == answer for answer in utils.negative_answers):
                    break
                if user_input == 'all' or user_input == 'a':  # reply is 'all'
                    batch_size = -1
                else:                    # wildcard 'yes' reply
                    batch_counter = 0
            print_search_result(service, index)
            index += 1
        print horizontal_bar
    except shodan.APIError, e:
        print 'Encountered error: %s' % e
        validate_still_logged_in()

    print 'Look up host from results? ',
    while(1):
        user_input = raw_input('Enter host index number (<num>/no): ')
        if any(user_input == answer for answer in utils.negative_answers):
            user_input = raw_input('Perform another search? (ENTER/no): ')
            if any(user_input == answer for answer in utils.negative_answers):
                print 'ShodanCLI shutting down.'
                sys.exit(1)
            else:
                break

        # Looking up host from results.
        val = check_int(user_input)
        if val < 0 or val > (index - 1) :
            print 'Invalid index, try again.',
            continue
        host_ip = results['matches'][val]['ip_str']
        try:
            host = api.host(host_ip)
            print_host_result(host)
        except shodan.APIError, e:
            print 'Encountered error: %s' % e
            continue







