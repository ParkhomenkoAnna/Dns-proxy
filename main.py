# /************************
# Author: Anna Parkhomenko
#
#
# DNS PROXY
# ************************/
from dnsproxy import *
from logger import *
import json
import os

logging = Logging()


def load_config(json_config="config.json"):
    if not os.path.isfile(json_config):
        logging.critical("ERROR! '{}' can not be opened".format(json_config))
        exit(0)
    with open(json_config) as json_data:
        config = json.load(json_data)
        if config:
            proxy_address = config.get("local-address")
            proxy_port = config.get("local-port")
            dns_address = config.get("dns_address")
            dns_port = config.get("dns-port")
            blacklist = config.get("blacklist")
            return proxy_address, proxy_port, dns_address, dns_port, blacklist
        else:
            logging.critical("ERROR! '{}' can not be found".format(config))


if __name__ == "__main__":
    """Test program dns-proxy.

       Usage: python main.py 

       Default host is localhost; default port is 53;
       Default dns server is 8.8.8.8.

       """
    proxy = dns_proxy(*load_config())
