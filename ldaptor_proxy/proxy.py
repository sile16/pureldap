#! /usr/bin/env python
# version 1


import sys
from ldapproxy import LDAPMappingProxy
from functools import partial
from twisted.internet.protocol import Factory
from twisted.internet import reactor, protocol
from twisted.python import log
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
import argparse


if __name__ == '__main__':
    """
    LDAP Usermapping proxy; listens on port 389 and
    passes all requests to backend server
    maps uids & gids on the way.
    """
    parser = argparse.ArgumentParser(description="Usermapping NIS LDAP Proxy.")

    parser.add_argument("server", help='IP or Hostname of LDAP server to send queries to.')
    parser.add_argument("-p","--port", help='port for backend LDAP server', default='389')
    args = parser.parse_args()

    log.startLogging(sys.stdout)
    factory = protocol.ServerFactory()
    Factory.noisy = False
    proxiedEndpointStr = 'tcp:host={}:port={}'.format(args.server, args.port)
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = LDAPMappingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(389, factory)
    reactor.run()
