"""IPCP negotiation: local address and DNS servers."""

from __future__ import annotations

import ipaddress

from .. import log
from . import frame
from .frame import ConfigureFsm

logger = log.get("ipcp")

OPTION_IP_ADDRESSES = 1
OPTION_IP_COMPRESSION = 2
OPTION_IP_ADDRESS = 3
OPTION_PRIMARY_DNS = 129
OPTION_PRIMARY_NBNS = 130
OPTION_SECONDARY_DNS = 131
OPTION_SECONDARY_NBNS = 132

UNSPECIFIED = b"\x00\x00\x00\x00"


def _address(value: bytes) -> str:
    return str(ipaddress.IPv4Address(value))


class Ipcp(ConfigureFsm):
    def __init__(self, send):
        super().__init__(frame.PPP_IPCP, "ipcp", send)
        # All zeroes asks the server to assign the values via Configure-Nak.
        self.options = {
            OPTION_IP_ADDRESS: UNSPECIFIED,
            OPTION_PRIMARY_DNS: UNSPECIFIED,
            OPTION_SECONDARY_DNS: UNSPECIFIED,
        }

    @property
    def local_address(self) -> str | None:
        value = self.options.get(OPTION_IP_ADDRESS, UNSPECIFIED)
        return _address(value) if value != UNSPECIFIED else None

    @property
    def peer_address(self) -> str | None:
        value = self.peer_options.get(OPTION_IP_ADDRESS)
        return _address(value) if value and value != UNSPECIFIED else None

    @property
    def dns_servers(self) -> list[str]:
        servers = []
        for option in (OPTION_PRIMARY_DNS, OPTION_SECONDARY_DNS):
            value = self.options.get(option, UNSPECIFIED)
            if value != UNSPECIFIED:
                servers.append(_address(value))
        return servers

    def review_peer_option(self, option_type: int, value: bytes):
        if option_type == OPTION_IP_ADDRESS:
            return "accept", b""
        if option_type == OPTION_IP_COMPRESSION:
            return "reject", b""
        return "reject", b""

    def apply_nak(self, option_type: int, value: bytes) -> None:
        if option_type in (
            OPTION_IP_ADDRESS,
            OPTION_PRIMARY_DNS,
            OPTION_SECONDARY_DNS,
        ):
            logger.debug("server assigned option %d = %s", option_type, _address(value))
            self.options[option_type] = value
        elif option_type in (OPTION_PRIMARY_NBNS, OPTION_SECONDARY_NBNS):
            # Accepted silently; NetBIOS name servers are of no use here.
            self.options.pop(option_type, None)
        else:
            self.options[option_type] = value
