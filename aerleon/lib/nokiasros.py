# Copyright 2024 Nokia All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Nokia SR OS ACL generator.

*[gl:/configure filter]
A:admin@sros# info json 
{
    "nokia-conf:ip-filter": [
        {
            "filter-name": "test",
            "entry": [
                {
                    "entry-id": 10,
                    "match": {
                        "ip": {
                            "ip-prefix-list": "test"
                        }
                    }
                },
                {
                    "entry-id": 20,
                    "match": {
                        "port": {
                            "port-list": "p2"
                        }
                    }
                }
            ]
        }
    ]
}

"""

import copy
import sys
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Set, Tuple

from aerleon.lib import aclgenerator, policy
from aerleon.lib.policy import Term

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict

# Graceful handling of dict hierarchy
def RecursiveDict() -> DefaultDict[Any, Any]:
    return defaultdict(RecursiveDict)

# generic error class
class Error(aclgenerator.Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class EstablishedWithNoProtocolError(Error):
    pass


class EstablishedWithNonTcpUdpError(Error):
    pass


class UnsupportedLogging(Error):
    pass


class SROSTerm(aclgenerator.Term):
    """Creates the term for the SR OS ACL."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}

    AF_RENAME = {
        4: 'ipv4',
        6: 'ipv6',
    }

    def __init__(self, term: policy.Term, inet_version: str = 'inet') -> None:
        super().__init__(term)
        self.term = term
        self.inet_version = inet_version

        # Combine (flatten) addresses with their exclusions into a resulting
        # flattened_saddr, flattened_daddr, flattened_addr.
        self.term.FlattenAll()

    def ConvertToDict(
        self,
    ) -> List:
        """Convert term to a dictionary.

        This is used to get a dictionary describing this term which can be
        output easily as an JSON blob. It represents an "acl-entry"
        message from the ACL schema.

        Returns:
          A list of dictionaries that contains all fields necessary to create or
          update an SROS acl-entry.
        """
        self.term_dict = RecursiveDict()

        # Rules will hold all exploded acl-entry dictionaries.
        rules = []

        # Convert the integer to the proper openconfig schema name str, ipv4/ipv6.
        term_af = self.AF_MAP.get(self.inet_version)
        family = self.AF_RENAME[term_af]

        self.SetName(self.term.name)

        # Action
        self.SetAction()

        # Ballot fatigue handling for 'any'.
        saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
        if not saddrs:
            saddrs = ['any']

        daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
        if not daddrs:
            daddrs = ['any']

        sports = self.term.source_port
        if not sports:
            sports = [(0, 0)]

        dports = self.term.destination_port
        if not dports:
            dports = [(0, 0)]

        protos = self.term.protocol
        if not protos:
            protos = ['none']

        self.term_dict = copy.deepcopy(self.term_dict)

        if self.term.comment:
            self.SetComments(self.term.comment)

        # Options, including logging
        self.SetOptions(family)

        # Source Addresses
        for saddr in saddrs:
            if saddr != 'any':
                self.SetSourceAddress(family, str(saddr))

            # Destination Addresses
            for daddr in daddrs:
                if daddr != 'any':
                    self.SetDestAddress(family, str(daddr))

                # Source Port
                for start, end in sports:
                    # 'any' starts and ends with zero.
                    if not start == end == 0:
                        self.SetSourcePorts(start, end)

                    # Destination Port
                    for start, end in dports:
                        if not start == end == 0:
                            self.SetDestPorts(start, end)

                        # Protocol
                        for proto in protos:
                            if isinstance(proto, str):
                                if proto != 'none':
                                    try:
                                        proto_num = self.PROTO_MAP[proto]
                                    except KeyError:
                                        raise Error(
                                            'Protocol %s unknown. Use an integer.', proto
                                        )
                                    self.SetProtocol(family, proto_num)
                            else:
                                self.SetProtocol(family, proto)

                            # This is the business end of ace explosion.
                            # A dict is a reference type, so deepcopy is actually required.
                            rules.append(copy.deepcopy(self.term_dict))

        return rules

    def SetName(self, name: str) -> None:
        # Put name in description field
        self.term_dict['description'] = name

    def SetAction(self) -> None:
        action = self.ACTION_MAP[self.term.action[0]]
        self.term_dict['action'] = action

    def SetComments(self, comments: List[str]) -> None:
        self.term_dict['_annotate_description'] = "_".join(comments)[:255]

    def SetOptions(self, family: str) -> None:
        # Handle various options
        opts = [str(x) for x in self.term.option]
        self.term_dict['match'] = {}
        if ('fragments' in opts) or ('is-fragment' in opts):
            self.term_dict['match']['fragment'] = True
        if 'first-fragment' in opts:
            self.term_dict['match']['first-fragment'] = True

        if 'initial' in opts or 'tcp-initial' in opts:
            self.term_dict['match']['tcp-flags'] = "syn"
        if 'rst' in opts:
            self.term_dict['match']['tcp-flags'] = (
                "syn rst" if 'tcp-flags' in self.term_dict['match'] else "rst"
            )
        # if 'not-syn-ack' in opts:
        #    self.term_dict['match']['tcp-flags'] = "!(syn&ack)"

        def _tcp_established():
            self.term_dict['match']['tcp-established'] = ""

        if 'tcp-established' in opts:
            if not self.term.protocol or self.term.protocol == ['tcp']:
                _tcp_established()
            else:
                raise TcpEstablishedWithNonTcpError(
                    f'tcp-established can only be used with tcp protocol in term {self.term.name}'
                )
        elif 'established' in opts:
            if self.term.protocol:
                if self.term.protocol == ['tcp']:
                    _tcp_established()
                elif self.term.protocol == ['udp']:
                    self.SetProtocol(family=family, protocol="udp")
                    if not self.term.destination_port:
                        self.SetDestPorts(1024, 65535)
                else:  # Could produce 2 rules if [tcp,udp]
                    raise EstablishedWithNonTcpUdpError(
                        f'established can only be used with tcp or udp protocol in term {self.term.name}'
                    )
            else:
                raise EstablishedWithNoProtocolError(
                    f'must specify a protocol for "established" in term {self.term.name}'
                )

        if 'tcp-flags' in self.term_dict['match']:
            self.SetProtocol(family=family, protocol="tcp")
        
        if self.term.logging:
            self.term_dict['log'] = 101 # XXX hardcoded

    def SetSourceAddress(self, family: str, saddr: str) -> None:
        self.term_dict['match']['src-ip'] = f'address {saddr}'

    def SetDestAddress(self, family: str, daddr: str) -> None:
        self.term_dict['match']['dst-ip'] = f'address {daddr}'

    def SetSourcePorts(self, start: int, end: int) -> None:
        if start == end:
            self.term_dict['match']['src-port'] = f'eq {start}'
        else:
            self.term_dict['match']['src-port'] = f'range start {start} end {end}'

    def SetDestPorts(self, start: int, end: int) -> None:
        if start == end:
            self.term_dict['match']['dst-port'] = f'eq {start}'
        else:
            self.term_dict['match']['dst-port'] = f'range start {start} end {end}'

    def SetProtocol(self, family: str, protocol: int) -> None:
        field_name = "protocol" if family == "ipv4" else "next-header"
        self.term_dict['match'][field_name] = protocol


class NokiaSROS(aclgenerator.ACLGenerator):
    """A Nokia SR OS ACL object, derived from ACLGenerator."""

    _PLATFORM = 'nokiasros'
    SUFFIX = '.sros_acl'

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        supported_tokens -= {'platform', 'platform_exclude', 'verbatim', 'icmp-type'}

        supported_sub_tokens['action'] = {'accept', 'deny'}  # excludes 'reject'
        supported_sub_tokens['option'] = {
            'established',
            'first-fragment',
            'is-fragment',
            'fragments',
            #  'sample',
            'tcp-established',
            'tcp-initial',
            #  'inactive',
            # 'not-syn-ack',
        }
        return supported_tokens, supported_sub_tokens

    def _InitACLSet(self) -> None:
        """Initialize self.acl_sets with proper Typing"""
        self.acl_sets: List[IPFilters] = []

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        self.total_rule_count = 0
        self._InitACLSet()

        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)

            # Options are anything after the platform name in the target message of
            # the policy header, [1:].

            # Get the address family if set.
            address_family = 'inet'
            for i in self._SUPPORTED_AF:
                if i in filter_options:
                    address_family = i
                    filter_options.remove(i)
            self._TranslateTerms(terms, address_family, filter_name, header.comment)

    def _TranslateTerms(
        self, terms: List[Term], address_family: str, filter_name: str, hdr_comments: List[str]
    ) -> None:
        acl_entries: List = []
        for term in terms:
            # Handle mixed for each indvidual term as inet and inet6.
            # inet/inet6 are treated the same.
            term_address_families = []
            if address_family == 'mixed':
                term_address_families = ['inet', 'inet6']
            else:
                term_address_families = [address_family]
            for term_af in term_address_families:
                t = SROSTerm(term,term_af)
                for rule in t.ConvertToDict():
                    self.total_rule_count += 1
                    rule['entry-id'] = (len(acl_entries) + 1) * 5
                    acl_entries.append(rule)
        desc = "_".join(hdr_comments)[:80] if hdr_comments else ""
        ip_filter = {
            'ip-filter'
            if address_family == 'inet'
            else 'ipv6-filter': {
                '_annotate': " ".join(aclgenerator.AddRepositoryTags()),
                'description': desc,
                'entry': acl_entries,
                'name': filter_name,
            }
        }
        self.acl_sets.append(ip_filter)

    def __str__(self) -> str:
        out = ""

        for s in self.acl_sets:
            for t in s:
                f = s[t]
                out += ( f"\n/configure filter {t} \"{f['name']}\" {{ description \"{f['description']}\"" )
                for e in f['entry']:
                    out += f"\nentry {e['entry-id']} {{ description \"{e['description']}\""
                    if 'log' in e:
                        out += f"\nlog {e['log']}"
                    for k,m in e["match"].items():
                      out += f"\nmatch {k} {m}"
                    out += f"\naction {e['action']}"
                    out += "\n}"
                out += "\n}"

        return out
