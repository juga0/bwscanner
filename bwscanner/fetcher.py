from twisted.internet import interfaces, reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.client import (SchemeNotSupported, Agent, BrowserLikePolicyForHTTPS)
from txsocksx.client import SOCKS5ClientFactory
from txsocksx.tls import TLSWrapClientEndpoint
from zope.interface import implementer

# from bwscanner.logger import log


def get_tor_socks_endpoint(tor_state):
    proxy_endpoint = tor_state.protocol.get_conf("SocksPort")

    def extract_port_value(result):
        # Get the first SOCKS port number if any. SocksPort can be a single string or a list.
        # Tor now also has support for unix domain SOCKS sockets so we need to be careful to just
        # pick a SOCKS port.
        if isinstance(result['SocksPort'], list):
            port = next(port for port in result['SocksPort'] if port.isdigit())
        else:
            port = result['SocksPort']

        return int(port) if port != 'DEFAULT' else 9050
    proxy_endpoint.addCallback(extract_port_value)
    proxy_endpoint.addCallback(
        lambda port: TCP4ClientEndpoint(reactor, '127.0.0.1', port))
    return proxy_endpoint
