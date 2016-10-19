## ShodanMiniCLI
Unofficial Shodan command-line interface. Discover popular user-shared search queries, search Shodan with/without filters and look-up discovered hosts.

**Usage:**

Run in interactive mode:
- `python SMC.py --key <YOUR_SHODAN_API_KEY>`

Run in script mode: (print to stdout and exit)
- `python SMC.py --key <YOUR_SHODAN_API_KEY> [options]`

[options] include:
- `--query <SEARCH_QUERY>`: General search query (e.g: "Akamai server")
- `--host <HOST>`: Specify hostname (e.g: 56.65.56.65)
- `--port <PORT>`: Specify port (e.g: 443)
- `--city <CITY>`: Specify city (e.g: "New York")
- `--country <COUNTRY>`: Specify country (e.g: "United States")
- `--os <OS>`: Specify operating system (e.g: "windows 2003")
- `--net <SUBNET>`: Specify subnet (e.g: "216.0.0.0/16")
- `--before <MAX_DATE>`: Specify latest date (e.g: "05/12/2016", "05-12-16")
- `--after <MIN_DATE>`: Specify oldest date (e.g: "26/10/1995", "26-10-95")

######Note: as usual, parameters with whitespaces in them (e.g: "New York") must be quoted.



**Requirements:**
- [Python 2.7](https://www.python.org/download/releases/2.7/)
- [Shodan Dev API key](https://developer.shodan.io/) (available in your profile page)
- [shodan-python](https://github.com/achillean/shodan-python) library (`pip install shodan`)
- [argparse](https://docs.python.org/2/howto/argparse.html) library (`pip install argparse`)


**Note:**

Shodan-python library contains the [official Shodan CLI](https://cli.shodan.io/), a fully-fleshed out interface. ('The' CLI)
