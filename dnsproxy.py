from dnsparse import *
from logger import *
import asyncio
import re

logging = Logging()
BLACKLIST = []

def is_allowed(domain_name):
    for entry in BLACKLIST:
        if re.search(entry, domain_name):
            return False
    return True



class DnsProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, dns_address):
        super().__init__()
        self.dns_address = dns_address
        self.remotes = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_event_loop()
        addr = DnsHandler(self, addr, data)
        dns_handler = loop.create_datagram_endpoint(lambda: addr, remote_addr=self.dns_address)
        asyncio.ensure_future(dns_handler)

    def error_received(self, exc):
        logging.critical('Error received:{}'.format(exc))


class DnsHandler(asyncio.DatagramProtocol):
    def __init__(self, proxy, client, data):
        super().__init__()
        self.proxy = proxy
        self.client = client
        self.data = data

    def connection_made(self, transport):
        self.transport = transport
        request = DnsPacket.parse(self.data)
        if is_allowed(str(request.questions.qname)):
            logging.info("New request from " + str(self.client) + ". Access permit to " + str(request.questions.qname))
            request_pack = DnsPacket.pack(request)
            self.transport.sendto(request_pack)
        else:
            flags = DnsFlags(qr='1', opcode='0000', aa='1', tc='0', ra='1', rd='0', rcode='0101')
            header = DnsHeader(request.header.id, flags, request.header.questions, 0, 0, 0)
            questions = DnsQueries(request.questions.qname, request.questions.qtype, request.questions.qclass)
            packet = DnsPacket(header, questions)
            response_pack = DnsPacket.pack(packet)
            logging.info("New request from " + str(self.client) + ". Access denied to " + str(request.questions.qname))
            self.proxy.transport.sendto(response_pack, self.client)

    def datagram_received(self, data, _):
        request = DnsPacket.parse(data)
        self.proxy.transport.sendto(data, self.client)

    def connection_lost(self, exc):
        self.proxy.remotes.pop(self.client)
        logging.critical('Error received:{}'.format(exc))


async def start_datagram_proxy(proxy_addr, proxy_port, dns_addr, dns_port):
    loop = asyncio.get_event_loop()
    protocol = DnsProxyProtocol((dns_addr, dns_port))
    return await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=(proxy_addr, proxy_port))


def dns_proxy(local_addr, local_port, dns_host, dns_port, blacklist):
    loop = asyncio.get_event_loop()
    global BLACKLIST
    BLACKLIST = blacklist
    proxy = start_datagram_proxy(local_addr, local_port, dns_host, dns_port)
    transport, _ = loop.run_until_complete(proxy)
    logging.critical("DNS proxy started...")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    logging.critical("DNS proxy stopped...")
    transport.close()
    loop.close()
