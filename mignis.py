#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Mignis - Semantic Based Firewall Configuration Tool

Mignis translates human-readable firewall rules into iptables format.
It provides an abstract, order-independent syntax for defining firewall
rules that are then translated to optimized iptables rulesets.

Features:
- Semantic rule syntax (easier to read and write than raw iptables)
- Order-independent rule processing
- Automatic rule optimization
- NAT support (SNAT, DNAT, Masquerade)
- NAT reflection/hairpinning support (allows LAN clients to access services via public IP)
- Egress bandwidth limits using Linux Traffic Control
- Formally verified translation (CSF 2014)

For usage instructions type:
$ ./mignis.py -h

Version: 0.9.6
Requires: Python 3.6+
'''

import argparse
import bisect
import hashlib
import json
import os
import pprint
import re
import shlex
import subprocess
import sys
import tempfile
import traceback

from collections import Counter, OrderedDict
from decimal import Decimal, InvalidOperation
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from ipaddr_ext import IPv4Range
from itertools import product
from typing import List, Dict, Tuple, Optional, Union, Any


class RuleException(Exception):
    pass


class Rule:
    # Reference to the Mignis object
    mignis = None
    # Dictionary with rule parameters
    params = {}

    def __init__(self,
                 mignis: 'Mignis',
                 abstract_rule: str,
                 abstract_rule_collapsed: str,
                 ruletype: str,
                 r_from: Optional[Tuple[str, Optional[List[int]]]],
                 r_to: Optional[Tuple[str, Optional[List[int]]]],
                 protocol: Optional[str],
                 filters: Optional[str],
                 nat: Optional[Tuple[str, Optional[List[int]]]]) -> None:
        '''Initialize a firewall rule.

        Args:
            mignis: Reference to the Mignis object
            abstract_rule: Rule as written in config (expanded)
            abstract_rule_collapsed: Rule as written in config (may include lists)
            ruletype: Type of rule (/, //, >, <>, >S, >M, >D)
            r_from: Source address specification
            r_to: Destination address specification
            protocol: Protocol (tcp, udp, icmp, etc.)
            filters: Custom iptables filters
            nat: NAT specification (for SNAT/DNAT rules)
        '''
        self.mignis = mignis

        if filters is None:
            filters = ''

        # Parse 'reflection' modifier for NAT hairpinning support
        # Syntax: ext > [public_ip:port] internal_server:port tcp | reflection
        # When enabled, generates additional rules for LAN clients to access
        # services using the gateway's public IP
        reflection = False
        if 'reflection' in filters:
            reflection = True
            filters = re.sub(r'\breflection\b', '', filters).strip()

        # Sanitize filters to prevent conflicting or dangerous options
        self._check_filters(filters)

        # Extract protocol from filters
        # filters, protocol = self._extract_protocol(filters)

        # Expand r_from, r_to and r_nat to aliases, interfaces, IPs and ports
        from_alias, from_intf, from_ip, from_port = self.expand_address(mignis, r_from)
        to_alias, to_intf, to_ip, to_port = self.expand_address(mignis, r_to)
        nat_alias, nat_intf, nat_ip, nat_port = self.expand_address(mignis, nat) if nat else (None, None, None, None)

        self.params = {
            # The rule as written in the configuration file (expanded)
            'abstract': abstract_rule,
            # The rule as written in the configuration file (collapsed, might include lists)
            'abstract_collapsed': abstract_rule_collapsed,
            # The type of rule, one of: /, //, >, <>, >S, >M, >D
            'rtype': ruletype,
            # Custom filters for the rule
            'filters': filters,
            'protocol': protocol,
            # From/To addresses
            'from_alias': from_alias,
            'from_intf': from_intf,
            'from_ip': from_ip,
            'from_port': from_port,
            'to_alias': to_alias,
            'to_intf': to_intf,
            'to_ip': to_ip,
            'to_port': to_port,
            # NAT options
            'nat_alias': nat_alias,
            'nat_intf': nat_intf,
            'nat_ip': nat_ip,
            'nat_port': nat_port,
            # NAT reflection (hairpinning)
            'reflection': reflection,
        }

    def __repr__(self):
        return pprint.pformat(self.params)

    @staticmethod
    def ruletype_str(ruletype: str) -> str:
        '''Convert ruletype code to human-readable string.'''
        if ruletype == '/':
            return 'Drop'
        elif ruletype == '//':
            return 'Reject'
        elif ruletype == '<>':
            return 'Forward (bidirectional)'
        elif ruletype == '>':
            return 'Forward'
        elif ruletype == '>D':
            return 'Destination Nat'
        elif ruletype == '>M':
            return 'Masquerade'
        elif ruletype == '>S':
            return 'Source Nat'
        elif ruletype == '{':
            return 'Sequence'
        else:
            raise RuleException('Invalid ruletype.')

    def _check_filters(self, filters: str) -> None:
        '''Verify that some options are not used inside filters.

        At the moment we look for:
        --dport, --dports, --destination-port, --destination-ports,
        --sport, --sports, --source-port, --source-ports,
        -s, --source, -d, --destination,
        -p, --protocol,
        -j, -C, -S, -F, -L, -Z, -N, -X, -P, -E
        '''
        check_regexp = (r'( |\A)('
                        r'--dport|--dports|--destination-port|--destination-ports|'
                        r'--sport|--sports|--source-port|--source-ports'
                        r')( |\Z)')
        invalid_option = re.search(check_regexp, filters)
        if invalid_option:
            raise RuleException(f'Invalid filter specified: {invalid_option.groups()[1]}.\n'
                                'You have to use the Mignis\'s syntax to specify ports.')
        check_regexp = (r'( |\A)('
                        #'-s|--source|-d|--destination|'
                        r'-p|--protocol|'
                        r'-j|-C|-S|-F|-L|-Z|-N|-X|-P|-E'
                        r')( |\Z)')
        invalid_option = re.search(check_regexp, filters)
        if invalid_option:
            raise RuleException(f'Invalid filter specified: {invalid_option.groups()[1]}.\n'
                                'You can\'t use this switch as a filter.')

    # def _extract_protocol(self, filters):
    #    '''Extract the protocol part from filters, and return the new filters
    #    string and protocol, if present.
    #    '''
    #    proto_regexp = '( |\A)(-p|--protocol) (.*?)( |\Z)'
    #    protocol = re.search(proto_regexp, filters)
    #    if protocol:
    #        filters = re.sub(proto_regexp, ' ', filters)
    #        protocol = protocol.groups()[2]
    #    else:
    #        protocol = None
    #    return filters, protocol

    @staticmethod
    def expand_address(mignis: 'Mignis',
                      addr: Optional[Tuple[str, Optional[List[int]]]]) -> Tuple[Optional[str],
                                                                                  Optional[str],
                                                                                  Optional[Union[IPv4Address, IPv4Network, IPv4Range]],
                                                                                  Optional[List[int]]]:
        '''Given an address in the form ([*|interface|ip|subnet], port)
        a tuple containing (alias, interface, ip, port) is returned.

        Note that ip can be either an IPv4Address, a list of IP addresses
        (in the case of an IP range) or an IPv4Network.
        '''
        ipsub, port = addr
        if ipsub == '*':
            alias = intf = ip = None
        elif ipsub in mignis.intf:
            alias = ipsub
            intf = mignis.intf[ipsub][0]
            # TODO: why only local has a subnet? every intf does have one.
            ip = mignis.intf['local'][1] if ipsub == 'local' else None
        else:
            if '/' in ipsub:
                # It's a custom subnet
                alias = intf = None
                ip = IPv4Network(ipsub, strict=True)
            elif '-' in ipsub:
                # It's a range of ip addresses
                alias = intf = None
                # ip = map(IPv4Address, ipsub.split('-'))
                ip = IPv4Range(ipsub)
                # if len(ip) != 2:
                #    raise Mignis.intfException(self, 'The range "{0}" is invalid.'.format(ipsub))
            else:
                ip = IPv4Address(ipsub)
                alias = Rule.ip2subnet(mignis, ip)
                if alias is None:
                    raise MignisException(mignis, f'The IP address "{ipsub}" does not belong to any subnet.')
                intf = mignis.intf[alias][0]
        return (alias, intf, ip, port)

    @staticmethod
    def ip2subnet(mignis: 'Mignis', ip: IPv4Address) -> Optional[str]:
        '''Returns the alias of the subnet the ip is in, or None if not found.'''
        # TODO: fix this for 0.0.0.0/0. We are doing a hack here to exclude 0.0.0.0/0 and
        # assign it only to an ip we don't know, which should be an external one in that case.
        all_addresses = None
        for alias in mignis.intf:
            subnet = mignis.intf[alias][1]
            if subnet == IPv4Network('0.0.0.0/0'):
                all_addresses = alias
                continue
            if subnet and ip in subnet:
                return alias
        else:
            return all_addresses

    def _format_intfip(self,
                      srcdst: str,
                      direction: str,
                      params: Dict[str, Any],
                      iponly: bool = False,
                      portonly: bool = False) -> str:
        '''Format interface/IP/port for iptables rules.

        Args:
            srcdst: 's' for source or 'd' for destination
            direction: 'from', 'to', or 'nat' - which param direction to use
            params: Rule parameters dictionary
            iponly: If True, return IP instead of interface
            portonly: If True, only return port specification

        Returns:
            String in format: '-[io] intf -[ds] ip --[sd]port port'
        '''
        intf_alias = f'{direction}_alias'
        intf = f'{direction}_intf'
        ip = f'{direction}_ip'
        port = f'{direction}_port'
        io = 'i' if srcdst == 's' else 'o'

        r = ''
        if not portonly:
            if params[ip]:
                # If there is an IP, we use that instead of the interface as it's more specific
                if isinstance(params[ip], IPv4Range):
                    srcdst_long = 'src' if srcdst == 's' else 'dst'
                    r = f'-m iprange --{srcdst_long}-range {params[ip]}'
                else:
                    r = f'-{srcdst} {params[ip]}'
            elif iponly:
                # We need to return an IP address instead of the interface,
                # but since no IP was explicitly specified, we have to return the subnet
                if params[intf_alias]:
                    subnet = self.mignis.intf[params[intf_alias]][1]
                    r = f'-{srcdst} {subnet}'
                else:
                    r = ''
            elif params[intf]:
                # If there is no IP, we use the interface
                r = f'-{io} {params[intf]}'
            else:
                # If there is no IP or interface, we don't add any filter
                r = ''

        if params[port]:
            r += f' --{srcdst}port {":".join(map(str, params[port]))}'

        return r

    def get_iptables_rules(self, rulesdict):
        params = self.params.copy()

        if self.params['rtype'] == '>':
            return self._forward(params)
        elif self.params['rtype'] == '<>':
            return self._dbl_forward(params)
        elif self.params['rtype'] == '/':
            return self._forward_deny(params)
        elif self.params['rtype'] == '//':
            return self._forward_deny(params, reject=True)
        elif self.params['rtype'] == '>M':
            return self._snat(params, masquerade=True)
        elif self.params['rtype'] == '>S':
            return self._snat(params)
        elif self.params['rtype'] == '>D':
            '''We will issue a warning in this situation:
            ext > lan
            ext > [lan] 10.0.0.1:1234

            If a rule is written this way the DNAT will take place anyway and the first rule will be useless.
            We won't check filters for this kind of match.
            We are going to do the check here because '>D' is translated after '>'.


            TODO (the checks below are missing and need to be implemented):
            ext > 1.1.1.1
            ext > [10.0.0.1] 1.1.1.1

            ext [1.1.1.2] > 1.1.1.1
            ext > [1.1.1.3] 1.1.1.1
            '''

            # FIXME: improve nat overlap check!
            # for rule in rulesdict['>']:
            #    if (rule.params['from_intf'] == params['from_intf'] and
            #            rule.params['to_intf'] == params['nat_intf']):
            #       self.mignis.warning('Forward and NAT rules collision:\n- {0}\n- {1}\n'
            #                    .format(rule.params['abstract'], params['abstract']))
            # TODO: should we check ports? otherwise isn't this warning too broad?

            return self._dnat(params)
        else:
            raise RuleException(f'Key error: invalid rule type \'{self.params["rtype"]}\'.')

    @staticmethod
    def ip_isinside(a, b):
        '''Returns True if a is inside b.
        a and b can be either None, IPv4Address or IPv4Network.
        '''
        a_class = type(a)
        b_class = type(b)

        if b is None:
            return True
        if a is None:
            # b is not None, while a is
            return False
        if b_class == IPv4Network:
            # a can be either an IPv4Network, an IPv4Range or an IPv4Address
            if a_class == IPv4Range:
                # we have to handle the match manually as ipaddr can't handle this
                # todo: we really should just extend the whole _BaseNet class in ipaddr.py
                return (int(b.network) <= a._ip_from and
                        int(b.broadcast) >= a._ip_to)
            else:
                return a in b
        if b_class == IPv4Range:
            # a can be either an IPv4Network, an IPv4Range or an IPv4Address
            return a in b
        elif b_class == IPv4Address and a_class == IPv4Address:
            return a == b

        # We are here if b_class == IPv4Address and a_class == IPv4Network or IPv4Range
        return False

    @staticmethod
    def port_isinside(a, b):
        '''Returns True if the port range a is inside b.
        a and b can be either None, or a list of length 2 maximum.
        '''
        if b is None:
            return True
        if a is None:
            # b is not None, while a is
            return False
        if len(b) == 1:
            # b is a port
            if len(a) == 1:
                # a is a port
                return a[0] == b[0]
            else:
                # a is a range
                return False
        else:
            # b is a range
            if len(a) == 1:
                # a is a port
                return a[0] >= b[0] and a[0] <= b[1]
            else:
                # a is a range
                return a[0] >= b[0] and a[1] <= b[1]

    def overlaps(self, a):
        '''Check if rule "a" is already matched by us (rule "b").
        At the moment we only match rules which are already matched by wider rules with empty filters.
        '''
        params_a = a.params
        params_b = self.params

        # If b has filters, rules don't overlap.
        # TODO: this is not so easy, we should improve the matching here
        if params_b['filters'] != '':
            return False

        # If from/to interfaces don't match, rules don't overlap.
        if not ((params_b['from_intf'] is None or params_a['from_intf'] == params_b['from_intf']) and
                (params_b['to_intf'] is None or params_a['to_intf'] == params_b['to_intf'])):
            return False

        # Check if from_ip and to_ip of a are subset of, respectively, from_ip and to_ip of b
        if not (Rule.ip_isinside(params_a['from_ip'], params_b['from_ip']) and
                Rule.ip_isinside(params_a['to_ip'], params_b['to_ip'])):
            return False

        # Do the same for ports
        if not (Rule.port_isinside(params_a['from_port'], params_b['from_port']) and
                Rule.port_isinside(params_a['to_port'], params_b['to_port'])):
            return False

        # Do the same for protocols
        protocol_a = params_a['protocol']
        protocol_b = params_b['protocol']
        if not (protocol_a == protocol_b or protocol_a == 'all' or protocol_b == 'all'):
            return False

        # This is used to avoid printing a warning when we are doing both SNAT/MASQERADE and DNAT
        # TODO: this is probably not the best way to perform this check
        if protocol_a == protocol_b and params_a['to_port'] == params_b['to_port'] and \
            params_a['from_intf'] == params_b['from_intf'] and \
            params_a['from_ip'] == params_b['from_ip'] and \
            params_a['to_ip'] == params_b['to_ip'] and \
            params_a['to_intf'] == params_b['to_intf'] and \
            ((params_a['rtype'] in ('>M', '>S') and params_b['rtype'] == '>D') or
             (params_b['rtype'] in ('>M', '>S') and params_a['rtype'] == '>D')):
            return False

        # Check if nat overlaps
        # TODO: do this

        return True

    def involves(self, alias, interface, ip):
        '''Given an alias, interface and ip
        check if it is involved in the rule.
        '''
        def check_involves(x):
            xintf = x + '_intf'
            xip = x + '_ip'

            return (
                (
                    interface == self.params[xintf] or
                    None in [interface, self.params[xintf]]
                ) and
                (Rule.ip_isinside(ip, self.params[xip]) or
                    Rule.ip_isinside(self.params[xip], ip) or
                    None in [ip, self.params[xip]]
                 )
            )

        # TODO: should "local" be involved by a rule with masquerade?
        # we skip masquerade at the moment! we should at least check if the ip
        # is one defined in the interfaces (when this will be added to interfaces...)

        checks = {
            'from': check_involves('from'),
            'to': check_involves('to'),
            'dnat': self.is_dnat() and check_involves('nat'),
            'snat': self.is_snat() and check_involves('nat'),
        }

        return (any(checks.values()), checks)

    def is_drop(self):
        return self.params['rtype'] == '/'

    def is_reject(self):
        return self.params['rtype'] == '//'

    def is_forward_dbl(self):
        return self.params['rtype'] == '<>'

    def is_forward(self):
        return self.params['rtype'] == '>'

    def is_dnat(self):
        return self.params['rtype'] == '>D'

    def is_snat(self):
        return self.params['rtype'] == '>S'

    def is_masquerade(self):
        return self.params['rtype'] == '>M'

    def is_sequence(self):
        return self.params['rtype'] == '{'

    def has_nat(self):
        return self.is_dnat() or self.is_snat() or self.is_masquerade()

    # Rule-translation functions

    @staticmethod
    def _format_protocol(params: Dict[str, Any]) -> str:
        '''Add the protocol to the rule.

        We need to add this before adding the --[ds]port switch as
        iptables won't recognize the -p switch if placed after --dport.
        '''
        # We add the protocol if a port or protocol have been specified.
        port = (('to_port' in params and params['to_port']) or
                ('from_port' in params and params['from_port']) or
                ('nat_port' in params and params['nat_port']))
        protocol = params['protocol'] if 'protocol' in params else None
        if port or protocol:
            if port and not protocol:
                # If a port has been specified without a protocol, add a default 'all' protocol.
                protocol = 'all'
            return ' -p ' + protocol
        return ''

    @staticmethod
    def format_rule(fmt: str, params: Dict[str, Any]) -> str:
        if 'abstract' in params:
            # Escape the " character
            params['rule_escaped'] = params['abstract'].replace('"', '\\"')
            fmt += ' -m comment --comment "{rule_escaped}"'
        params['proto'] = Rule._format_protocol(params)
        rule = re.sub(' +', ' ', fmt.format(**params))
        return rule

    def _forward(self, params: Dict[str, Any], flip: bool = False) -> List[str]:
        '''Translation for ">".

        If flip is True, the 'to' and 'from' parameters are switched
        (this only happens for the non-local case).
        '''
        rules = []
        if params['from_alias'] == 'local' or params['to_alias'] == 'local':
            # local case
            dir1 = 'from'
            dir2 = 'to'
        else:
            # forward case
            dir1 = 'to' if flip else 'from'
            dir2 = 'from' if flip else 'to'

        if params['from_alias'] == 'local' and params['to_alias'] == 'local':
            # OUTPUT and INPUT rule (this is the "local > local" case)
            # TODO: we can avoid this and use the same code as 'from_alias', so by exploiting the generic "established,related" rule
            # but as we know how to do it without it, maybe it's better? We should think about it.
            params['source'] = self._format_intfip('s', dir1, params, portonly=True)
            params['destination'] = self._format_intfip('d', dir2, params)
            rules.append(self.format_rule('-A OUTPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
            params['source'] = self._format_intfip('s', dir2, params)
            params['destination'] = self._format_intfip('d', dir1, params, portonly=True)
            rules.append(self.format_rule('-A INPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
        elif params['from_alias'] == 'local':
            # OUTPUT rule
            if flip:
                params['source'] = self._format_intfip('s', dir2, params)
                params['destination'] = self._format_intfip('d', dir1, params, portonly=True)
                rules.append(self.format_rule('-A INPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
            else:
                params['source'] = self._format_intfip('s', dir1, params, portonly=True)
                params['destination'] = self._format_intfip('d', dir2, params)
                rules.append(self.format_rule('-A OUTPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
        elif params['to_alias'] == 'local':
            # INPUT rule
            if flip:
                params['source'] = self._format_intfip('s', dir2, params, portonly=True)
                params['destination'] = self._format_intfip('d', dir1, params)
                rules.append(self.format_rule('-A OUTPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
            else:
                params['source'] = self._format_intfip('s', dir1, params)
                params['destination'] = self._format_intfip('d', dir2, params, portonly=True)
                rules.append(self.format_rule('-A INPUT {proto} {source} {destination} {filters} -j ACCEPT', params))
        else:
            # FORWARD rule
            params['source'] = self._format_intfip('s', dir1, params)
            params['destination'] = self._format_intfip('d', dir2, params)
            rules.append(self.format_rule('-A FORWARD {proto} {source} {destination} {filters} -j ACCEPT', params))
        return rules

    def _dbl_forward(self, params: Dict[str, Any]) -> List[str]:
        '''Translation for "<>" (bidirectional forward).'''
        rules = []
        rules.extend(self._forward(params))
        rules.extend(self._forward(params, flip=True))
        return rules

    def _forward_deny(self, params, reject=False):
        '''Translation for "/" and "//"
        '''
        rules = []

        target = 'REJECT' if reject else 'DROP'
        if params['from_alias'] == 'local':
            # OUTPUT rule
            # this also matches the "local / local" rule
            params['source'] = self._format_intfip('s', 'from', params, portonly=True)
            params['destination'] = self._format_intfip('d', 'to', params)
            chain = 'OUTPUT'
        elif params['to_alias'] == 'local':
            # INPUT rule
            params['source'] = self._format_intfip('s', 'from', params)
            params['destination'] = self._format_intfip('d', 'to', params, portonly=True)
            chain = 'INPUT'
        else:
            # FORWARD rule
            params['source'] = self._format_intfip('s', 'from', params)
            params['destination'] = self._format_intfip('d', 'to', params)
            chain = 'FORWARD'
        rules.append(
            self.format_rule('-A ' + chain + ' {proto} {source} {destination} {filters} -j ' + target, params))

        return rules

    def _snat(self, params: Dict[str, Any], masquerade: bool = False) -> List[str]:
        '''Translation for ">" in the case of a SNAT.'''
        rules = []
        rules.extend(self._forward(params))

        if masquerade:
            target = 'MASQUERADE'
        else:
            params['nat'] = str(params['nat_ip'])
            if params['nat_port']:
                params['nat'] += ':' + '-'.join(map(str, params['nat_port']))
            target = 'SNAT --to-source {nat}'
        params['source'] = self._format_intfip('s', 'from', params, iponly=True)
        params['destination'] = self._format_intfip('d', 'to', params)
        rules.append(
            self.format_rule('-t nat -A POSTROUTING {proto} {source} {destination} {filters} -j ' + target, params))
        return rules

    def _dnat(self, params: Dict[str, Any]) -> List[str]:
        '''Translate DNAT (Destination NAT) rules.

        Generates iptables rules for destination NAT, optionally with NAT reflection.

        DNAT allows external traffic to be redirected to internal servers. When the
        'reflection' modifier is enabled, it also generates hairpinning rules so that
        LAN clients can access services using the gateway's public IP.

        Generated rules:
        1. Mangle table DROP rule (prevents NAT bypass via internal IP)
        2. Forward rule (allows the traffic through)
        3. NAT PREROUTING/OUTPUT rule (performs the actual DNAT)
        4. If reflection enabled: Additional DNAT + SNAT rules for each LAN interface

        Args:
            params: Dictionary containing rule parameters (from, to, nat, protocol, etc.)

        Returns:
            List of iptables rule strings
        '''
        rules = []
        if re.search('(^| )-m state ', params['filters']):
            self.mignis.warning('Inspectioning the state in DNAT might corrupt the rule.' +
                                f'Use it only if you know what you\'re doing.\n- {params["abstract"]}')

        params['source'] = self._format_intfip('s', 'from', params)
        params['destination'] = self._format_intfip('d', 'to', params, iponly=True)
        rules.append(self.format_rule(
            '-t mangle -A PREROUTING {proto} {source} {destination} {filters} -m state --state NEW -j DROP', params))

        # Forward rules without filters
        filters = params['filters']
        params['filters'] = ''
        rules.extend(self._forward(params))
        params['filters'] = filters

        if params['from_alias'] == 'local':
            params['source'] = self._format_intfip('s', 'from', params, portonly=True)
            params['chain'] = 'OUTPUT'
        else:
            params['source'] = self._format_intfip('s', 'from', params)
            params['chain'] = 'PREROUTING'

        params['destination'] = self._format_intfip('d', 'nat', params, iponly=True)
        # TODO: verify that to_ip is not None.
        params['nat'] = str(params['to_ip'])
        if params['to_port']:
            params['nat'] += ':' + '-'.join(map(str, params['to_port']))
        rules.append(self.format_rule(
            '-t nat -A {chain} {proto} {source} {destination} {filters} -j DNAT --to-destination {nat}', params))

        # ========================================================================
        # NAT REFLECTION (HAIRPINNING) SUPPORT
        # ========================================================================
        # When 'reflection' modifier is enabled, generate additional rules to allow
        # LAN clients to access services using the gateway's public IP.
        #
        # Problem: Without reflection, when a LAN client (192.168.1.50) tries to
        # access the public IP (1.2.3.4:80), the traffic doesn't match the normal
        # DNAT rule (which only matches traffic from the WAN interface).
        #
        # Solution: For each LAN interface, generate:
        # 1. DNAT: LAN -> public_ip:port => internal_server:port
        # 2. SNAT (MASQUERADE): source becomes router IP
        #    This ensures return traffic goes through the router, not directly
        #    back to the client (which would cause connection failure)
        #
        # Example flow for client 192.168.1.50 accessing 1.2.3.4:80:
        #   Client sends: 192.168.1.50:12345 -> 1.2.3.4:80
        #   After DNAT:   192.168.1.50:12345 -> 192.168.1.100:80 (internal server)
        #   After SNAT:   192.168.1.1:54321 -> 192.168.1.100:80 (router IP)
        #   Server sees request from router, replies to router
        #   Router translates back and sends to client
        # ========================================================================
        if params['reflection']:
            wan_intf = params['from_intf']  # Interface where external traffic arrives
            # Use the pub= IP if configured on the WAN interface (double NAT scenario),
            # otherwise fall back to the DNAT destination IP (nat_ip)
            from_alias = params['from_alias']
            pub_ip = self.mignis.intf[from_alias][3] if from_alias in self.mignis.intf else None
            public_ip = pub_ip or params['nat_ip']
            public_port = params['nat_port'] # Public port
            internal_ip = params['to_ip']    # Internal server IP
            internal_port = params['to_port'] # Internal server port

            # Iterate over all non-WAN interfaces to generate hairpin rules
            for intf_alias, (intf_name, intf_subnet, intf_options, _) in self.mignis.intf.items():
                # Skip WAN interfaces (marked with 'wan' tag), loopback, and the WAN source interface
                if 'wan' in intf_options or intf_alias == 'local' or intf_name == wan_intf:
                    continue

                # FORWARD rule: Allow hairpin traffic from this LAN interface to the internal server
                # Without this, the default FORWARD DROP policy blocks the redirected traffic
                # since the original FORWARD rule only allows traffic from the WAN interface.
                hairpin_params = params.copy()
                hairpin_params['source'] = f'-i {intf_name}'
                hairpin_params['destination'] = f'-d {internal_ip}'
                if internal_port:
                    hairpin_params['destination'] += f' --dport {":".join(map(str, internal_port))}'
                rules.append(self.format_rule(
                    '-A FORWARD {proto} {source} {destination} -j ACCEPT',
                    hairpin_params))

                # DNAT rule: Traffic from LAN to public IP gets redirected to internal server
                hairpin_params['source'] = f'-i {intf_name}'
                hairpin_params['destination'] = f'-d {public_ip}'
                if public_port:
                    hairpin_params['destination'] += f' --dport {":".join(map(str, public_port))}'

                rules.append(self.format_rule(
                    '-t nat -A PREROUTING {proto} {source} {destination} -j DNAT --to-destination {nat}',
                    hairpin_params))

                # MASQUERADE rule: Rewrite source IP to the router's IP on the outgoing interface
                # This is CRITICAL for hairpinning to work. Without SNAT, the internal
                # server would see the client's LAN IP as source and reply directly to
                # the client, bypassing the router. The client would reject the reply
                # because it expects a response from the public IP, not the internal IP.
                #
                # We use MASQUERADE (not SNAT with public IP) because the hairpin traffic
                # exits via a LAN interface, not a WAN interface. MASQUERADE automatically
                # uses the router's IP on that LAN interface, ensuring the internal server
                # replies back through the router for proper de-NAT.
                if intf_subnet:
                    hairpin_params['source'] = f'-s {intf_subnet}'
                    hairpin_params['destination'] = f'-d {internal_ip}'
                    if internal_port:
                        hairpin_params['destination'] += f' --dport {":".join(map(str, internal_port))}'

                    rules.append(self.format_rule(
                        '-t nat -A POSTROUTING {proto} {source} {destination} -j MASQUERADE',
                        hairpin_params))

        return rules
    ##


class MignisException(Exception):

    def __init__(self, mignis, message):
        Exception.__init__(self, message)
        # mignis.reset_iptables(False)


class MignisConfigException(Exception):
    pass


class TrafficLimit:
    '''A traffic shaping rule applied to one side of an interface.'''

    RATE_MULTIPLIERS = {
        'bit': Decimal(1),
        'kbit': Decimal(1000),
        'mbit': Decimal(1000 * 1000),
        'gbit': Decimal(1000 * 1000 * 1000),
    }

    def __init__(self,
                 interface_alias: str,
                 interface: str,
                 source: Optional[Union[IPv4Address, IPv4Network]],
                 destination: Optional[Union[IPv4Address, IPv4Network]],
                 source_text: str,
                 destination_text: str,
                 rate: str,
                 abstract: str,
                 direction: str = 'egress') -> None:
        self.interface_alias = interface_alias
        self.interface = interface
        self.direction = direction
        self.source = source
        self.destination = destination
        self.source_text = source_text
        self.destination_text = destination_text
        self.rate = rate.lower()
        self.rate_bps = self._parse_rate(self.rate)
        self.abstract = abstract
        self.class_minor = None
        self.mark = None

    @classmethod
    def _parse_rate(cls, rate: str) -> int:
        match = re.fullmatch(r'([1-9][0-9]*(?:\.[0-9]+)?)(bit|kbit|mbit|gbit)', rate.lower())
        if not match:
            raise MignisConfigException(
                f'Invalid traffic limit rate "{rate}". '
                'Use a positive value followed by bit, kbit, mbit or gbit.')

        try:
            bits_per_second = Decimal(match.group(1)) * cls.RATE_MULTIPLIERS[match.group(2)]
        except InvalidOperation:
            raise MignisConfigException(f'Invalid traffic limit rate "{rate}".')

        if bits_per_second < 1000:
            raise MignisConfigException(
                f'Traffic limit rate "{rate}" is too small; the minimum supported rate is 1kbit.')
        return int(bits_per_second)

    @property
    def is_interface_limit(self) -> bool:
        return self.source is None and self.destination is None

    @staticmethod
    def _interval(address: Optional[Union[IPv4Address, IPv4Network]]) -> Tuple[int, int]:
        if address is None:
            return (0, (1 << 32) - 1)
        if isinstance(address, IPv4Network):
            return (int(address.network_address), int(address.broadcast_address))
        value = int(address)
        return (value, value)

    def overlaps(self, other: 'TrafficLimit') -> bool:
        if self.interface != other.interface or self.direction != other.direction:
            return False

        self_source = self._interval(self.source)
        other_source = self._interval(other.source)
        self_destination = self._interval(self.destination)
        other_destination = self._interval(other.destination)

        source_overlaps = self_source[0] <= other_source[1] and other_source[0] <= self_source[1]
        destination_overlaps = (
            self_destination[0] <= other_destination[1] and
            other_destination[0] <= self_destination[1]
        )
        return source_overlaps and destination_overlaps

    def sort_key(self) -> Tuple[Any, ...]:
        source = self._interval(self.source)
        destination = self._interval(self.destination)
        return (
            self.direction,
            self.interface,
            source[0],
            source[1],
            destination[0],
            destination[1],
            self.rate_bps,
        )

    def iptables_match(self) -> str:
        if self.direction != 'egress':
            raise MignisConfigException('Only egress traffic limits use iptables marks.')
        parts = [f'-o {self.interface}']
        if self.source is not None:
            parts.append(f'-s {self.source}')
        if self.destination is not None:
            parts.append(f'-d {self.destination}')
        return ' '.join(parts)

    @staticmethod
    def _flower_address(address: Union[IPv4Address, IPv4Network]) -> str:
        if isinstance(address, IPv4Address):
            return f'{address}/32'
        return str(address)

    def flower_match(self) -> str:
        if self.direction != 'ingress':
            raise MignisConfigException('Only ingress traffic limits use flower selectors.')
        parts = []
        if self.source is not None:
            parts.append(f'src_ip {self._flower_address(self.source)}')
        if self.destination is not None:
            parts.append(f'dst_ip {self._flower_address(self.destination)}')
        return ' '.join(parts)


class Mignis:
    '''Main Mignis firewall configuration manager.

    This class handles:
    - Reading and parsing configuration files
    - Translating semantic rules to iptables format
    - Managing interfaces and network aliases
    - Generating optimized iptables rulesets
    - Writing/applying rules to the system

    Attributes:
        intf: Dictionary mapping interface aliases to (name, subnet, options, pub_ip)
              Example: {'lan': ('eth0', IPv4Network('10.0.0.0/24'), [], None),
                       'ext': ('eth1', IPv4Network('0.0.0.0/0'), ['wan'], IPv4Address('93.92.241.21'))}
              The 'wan' option marks WAN interfaces for NAT reflection.
              The pub_ip is the real public IP for double NAT scenarios (from pub= option).
        iptables_rules: List of generated iptables rule strings
        old_rules: Previously applied rules (for rollback)
        aliases: IP address aliases for cleaner rule syntax
        fw_rulesdict: Parsed firewall rules organized by type
        options: Configuration options (logging, default_rules, etc.)
    '''
    old_rules = []
    intf = {}
    iptables_rules = []

    TC_CHAIN = 'MIGNIS_TC'
    TC_ROOT_HANDLE = '1d00:'
    TC_ROOT_MAJOR = '1d00'
    TC_DEFAULT_MINOR = 0x2
    TC_FIRST_FLOW_MINOR = 0x10
    TC_LEAF_MAJOR = 0x1e00
    TC_MARK_MASK = 0xffff0000
    TC_MARK_SHIFT = 16
    TC_INGRESS_FILTER_PRIORITY = 49152
    TC_INGRESS_FILTER_HANDLE = 1
    TC_STATE_VERSION = 2
    TC_STATE_FILE = '/run/mignis/tc-state.json'

    def __init__(self, config_file, debug, force, dryrun, write_rules_filename, execute_rules, flush):
        # These used to be class attributes. Keep all generated state per instance,
        # otherwise multiple Mignis objects in the same process leak rules into one another.
        self.old_rules = []
        self.intf = {}
        self.iptables_rules = []
        self.tc_rules = []
        self.traffic_limits = []
        self.traffic_limit_groups = {}
        self.config_file = config_file
        self.debug = debug
        self.force = force
        self.dryrun = dryrun
        self.write_rules_filename = write_rules_filename
        self.execute_rules = execute_rules
        self.flush = flush
        # The config file should not be parsed and only flush rules should be generated
        if self.flush:
            self.all_rules = self.flush_rules
        else:
            self.read_config()

    def wr(self, s):
        '''Print a string to stdout
        '''
        if self.debug >= 1:
            print(s)

    def execute(self, command, capture_output=False):
        '''Execute a command without invoking a shell.'''
        if self.dryrun:
            return None

        if self.debug >= 2:
            print('COMMAND: ' + ' '.join(command))

        try:
            result = subprocess.run(
                command,
                check=False,
                universal_newlines=True,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise MignisException(
                self, f'Unable to execute "{command[0]}": {error}')

        if result.returncode:
            detail = result.stderr.strip()
            message = f'Command execution error (code: {result.returncode}).'
            if detail:
                message += '\n' + detail
            raise MignisException(self, message)
        return result

    def test_exec_rules(self):
        # Create temp file for writing the rules
        temp_fd, temp_file = tempfile.mkstemp(suffix='.ipt', prefix='mignis_')
        self.write_rules(None, fd=temp_fd)

        # Execute the rules.
        # First in dryrun mode, and if no exception is raised they are executed for real.
        self.exec_rules(temp_file, force_dryrun=True)
        self.exec_rules(temp_file)

        # Delete the temp file
        os.unlink(temp_file)

    def exec_rules(self, temp_file, force_dryrun=False):
        command = ['iptables-restore']
        if self.dryrun or force_dryrun:
            command.append('--test')
        command.append(temp_file)

        try:
            # Execute the rules
            self.execute(command)
        except MignisException as e:
            raise MignisException(
                self, str(e) + '\nThe temporary file which generated the error is stored in "{0}"'.format(temp_file))

    def write_rules(self, filename, fd=None, output_checked=False):
        if self.dryrun:
            return

        if fd is not None:
            f = os.fdopen(fd, 'w')
        else:
            if not output_checked and not self.force and os.path.exists(filename):
                raise MignisException(self, 'The file already exists, use -f to overwrite.')
            f = open(filename, 'w')

        if self.flush:
            # We just need to write the rules to file
            for rule in self.iptables_rules:
                f.write(rule.strip() + '\n')
        else:
            # Split the rules in filter, nat and mangle tables
            separators = r'[^a-zA-Z0-9\-_]'
            rules = self.iptables_rules[:]
            tables = {'filter': [], 'nat': [], 'mangle': []}
            for table, table_opt in [
                    ('nat', rf'(?:\A|{separators})(-t nat)(?:\Z|{separators})'),
                    ('mangle', rf'(?:\A|{separators})(-t mangle)(?:\Z|{separators})')]:
                for rule in self.iptables_rules:
                    if re.search(table_opt, rule):
                        # Extract the rule without "-t nat" or "-t mangle" switches
                        rules.remove(rule)
                        rule = re.sub(table_opt, '', rule)
                        tables[table].append(rule)
            tables['filter'] = rules

            # Write the rules by table
            for table_name, rules in tables.items():
                f.write('*' + table_name + '\n')
                f.write('\n'.join(rules))
                f.write('\nCOMMIT\n')

        f.close()

    def write_tc_rules(self, filename, fd=None, output_checked=False):
        if self.dryrun or not self.tc_rules:
            return

        if fd is not None:
            f = os.fdopen(fd, 'w')
        else:
            if not output_checked and not self.force and os.path.exists(filename):
                raise MignisException(self, 'The file already exists, use -f to overwrite.')
            f = open(filename, 'w')

        for rule in self.tc_rules:
            f.write(rule + '\n')
        f.close()

    def write_tc_runner(self, filename, tc_filename, output_checked=False):
        '''Write a small runner that creates IFBs before loading a tc batch.'''
        ingress_groups = self._traffic_groups('ingress')
        if self.dryrun or not ingress_groups:
            return

        if not output_checked and not self.force and os.path.exists(filename):
            raise MignisException(self, 'The file already exists, use -f to overwrite.')

        with open(filename, 'w') as runner:
            runner.write('#!/bin/sh\n\nset -eu\n\n')
            for group in ingress_groups:
                interface = group['interface']
                ifb = group['device']
                alias = self._ifb_alias(interface)
                quoted_interface = shlex.quote(interface)
                quoted_ifb = shlex.quote(ifb)
                quoted_alias = shlex.quote(alias)
                alias_path = shlex.quote(f'/sys/class/net/{ifb}/ifalias')

                runner.write(
                    f'if ip link show dev {quoted_ifb} >/dev/null 2>&1; then\n'
                    f'    if ! ip -d link show dev {quoted_ifb} | grep -q " ifb "; then\n'
                    f'        echo "Refusing to reuse non-IFB interface {ifb}" >&2\n'
                    '        exit 1\n'
                    '    fi\n'
                    f'    if [ "$(cat {alias_path})" != {quoted_alias} ]; then\n'
                    f'        echo "Refusing to reuse IFB {ifb} not owned by Mignis" >&2\n'
                    '        exit 1\n'
                    '    fi\n'
                    'else\n'
                    f'    ip link add name {quoted_ifb} type ifb\n'
                    f'    ip link set dev {quoted_ifb} alias {quoted_alias}\n'
                    'fi\n'
                    f'ip link set dev {quoted_ifb} up\n'
                    f'if ! tc qdisc show dev {quoted_interface} | '
                    'grep -q "^qdisc clsact "; then\n'
                    f'    tc qdisc add dev {quoted_interface} clsact\n'
                    'fi\n'
                    f'tc filter del dev {quoted_interface} ingress protocol all '
                    f'priority {self.TC_INGRESS_FILTER_PRIORITY} '
                    f'handle {self.TC_INGRESS_FILTER_HANDLE} matchall '
                    '2>/dev/null || true\n\n'
                )

            for device in sorted({
                    group['device'] for group in self._traffic_groups()}):
                quoted_device = shlex.quote(device)
                runner.write(
                    f'if tc qdisc show dev {quoted_device} | '
                    f'grep -q "^qdisc htb {self.TC_ROOT_HANDLE}"; then\n'
                    f'    tc qdisc del dev {quoted_device} root\n'
                    'fi\n'
                )
            runner.write('\n')

            quoted_batch = shlex.quote(os.path.basename(tc_filename))
            runner.write(
                'script_directory=$(CDPATH=\'\' cd -- "$(dirname -- "$0")" && pwd)\n'
                f'exec tc -batch "$script_directory"/{quoted_batch}\n'
            )
        os.chmod(filename, 0o755)

    def write_all_rules(self, filename):
        output_files = [filename]
        tc_filename = filename + '.tc'
        tc_runner_filename = filename + '.tc.sh'
        if self.tc_rules:
            output_files.append(tc_filename)
        if self._traffic_groups('ingress'):
            output_files.append(tc_runner_filename)

        if not self.force:
            for output_file in output_files:
                if os.path.exists(output_file):
                    raise MignisException(
                        self, f'The file "{output_file}" already exists, use -f to overwrite.')

        self.write_rules(filename, output_checked=True)
        if self.tc_rules:
            self.write_tc_rules(tc_filename, output_checked=True)
        if self._traffic_groups('ingress'):
            self.write_tc_runner(
                tc_runner_filename,
                tc_filename,
                output_checked=True,
            )
        return output_files

    def _tc_state_path(self):
        return os.environ.get('MIGNIS_TC_STATE_FILE', self.TC_STATE_FILE)

    @staticmethod
    def _empty_tc_state():
        return {
            'egress': set(),
            'ingress': {},
        }

    @staticmethod
    def _valid_tc_interface(interface):
        return (
            isinstance(interface, str) and
            re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', interface) is not None
        )

    def _load_tc_state(self):
        state_path = self._tc_state_path()
        if not os.path.exists(state_path):
            return self._empty_tc_state()

        try:
            with open(state_path) as state_file:
                state = json.load(state_file)

            # Version 1 tracked only egress interfaces. Accept it so upgrading
            # does not orphan an existing Mignis HTB root.
            if state.get('version') == 1:
                interfaces = state.get('interfaces')
                if not isinstance(interfaces, list):
                    raise ValueError('invalid interface list')
                if not all(self._valid_tc_interface(interface)
                           for interface in interfaces):
                    raise ValueError('invalid interface name')
                return {
                    'egress': set(interfaces),
                    'ingress': {},
                }

            if state.get('version') != self.TC_STATE_VERSION:
                raise ValueError('unsupported state version')

            egress_interfaces = state.get('egress')
            ingress_interfaces = state.get('ingress')
            if not isinstance(egress_interfaces, list):
                raise ValueError('invalid egress interface list')
            if not all(self._valid_tc_interface(interface)
                       for interface in egress_interfaces):
                raise ValueError('invalid interface name')

            if not isinstance(ingress_interfaces, dict):
                raise ValueError('invalid ingress interface map')
            normalized_ingress = {}
            for interface, ingress_state in ingress_interfaces.items():
                if not self._valid_tc_interface(interface):
                    raise ValueError('invalid ingress interface name')
                if not isinstance(ingress_state, dict):
                    raise ValueError('invalid ingress interface state')
                ifb = ingress_state.get('ifb')
                owns_clsact = ingress_state.get('owns_clsact')
                if (not self._valid_tc_interface(ifb) or
                        ifb != self._ifb_name(interface) or
                        not isinstance(owns_clsact, bool)):
                    raise ValueError('invalid ingress interface state')
                normalized_ingress[interface] = {
                    'ifb': ifb,
                    'owns_clsact': owns_clsact,
                }

            return {
                'egress': set(egress_interfaces),
                'ingress': normalized_ingress,
            }
        except (OSError, AttributeError, ValueError, TypeError, json.JSONDecodeError) as error:
            self.warning(f'Ignoring invalid traffic-control state "{state_path}": {error}')
            return self._empty_tc_state()

    def _save_tc_state(self, state):
        state_path = self._tc_state_path()
        state_directory = os.path.dirname(state_path) or '.'
        egress_interfaces = set(state['egress'])
        ingress_interfaces = state['ingress']

        if not egress_interfaces and not ingress_interfaces:
            if os.path.exists(state_path):
                os.unlink(state_path)
            return

        temporary_state = None
        try:
            os.makedirs(state_directory, exist_ok=True)
            state_fd, temporary_state = tempfile.mkstemp(
                prefix='.tc-state-', suffix='.json', dir=state_directory)
            with os.fdopen(state_fd, 'w') as state_file:
                json.dump({
                    'version': self.TC_STATE_VERSION,
                    'egress': sorted(egress_interfaces),
                    'ingress': {
                        interface: ingress_interfaces[interface]
                        for interface in sorted(ingress_interfaces)
                    },
                }, state_file)
                state_file.write('\n')
            os.replace(temporary_state, state_path)
        except OSError as error:
            if temporary_state and os.path.exists(temporary_state):
                try:
                    os.unlink(temporary_state)
                except OSError:
                    pass
            raise MignisException(
                self, f'Unable to save traffic-control state "{state_path}": {error}')

    def _parse_json_command(self, command, description):
        result = self.execute(
            command,
            capture_output=True,
        )
        try:
            parsed = json.loads(result.stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise MignisException(
                self, f'Unable to parse {description}: {error}')
        if not isinstance(parsed, list):
            raise MignisException(self, f'Invalid JSON returned for {description}.')
        return parsed

    def _qdiscs(self, interface):
        return self._parse_json_command(
            ['tc', '-j', 'qdisc', 'show', 'dev', interface],
            f'tc state for interface "{interface}"',
        )

    def _root_qdisc(self, interface):
        for qdisc in self._qdiscs(interface):
            if qdisc.get('root') is True:
                return qdisc
        return None

    def _ingress_qdisc(self, interface):
        for qdisc in self._qdiscs(interface):
            if qdisc.get('kind') in ('clsact', 'ingress'):
                return qdisc
        return None

    def _link_info(self, interface):
        links = self._parse_json_command(
            ['ip', '-j', '-d', 'link', 'show'],
            'network interface state',
        )
        for link in links:
            if link.get('ifname') == interface:
                return link
        return None

    def _ingress_filters(self, interface):
        return self._parse_json_command(
            ['tc', '-j', 'filter', 'show', 'dev', interface, 'ingress'],
            f'ingress filters for interface "{interface}"',
        )

    def _is_mignis_qdisc(self, qdisc):
        return (
            qdisc is not None and
            qdisc.get('kind') == 'htb' and
            str(qdisc.get('handle', '')).lower() == self.TC_ROOT_HANDLE
        )

    def _is_mignis_ifb(self, link, interface):
        return (
            link is not None and
            link.get('linkinfo', {}).get('info_kind') == 'ifb' and
            link.get('ifalias') == self._ifb_alias(interface)
        )

    def _is_mignis_redirect(self, traffic_filter, ifb):
        if (traffic_filter.get('pref') != self.TC_INGRESS_FILTER_PRIORITY or
                traffic_filter.get('kind') != 'matchall'):
            return False
        options = traffic_filter.get('options')
        if not isinstance(options, dict):
            return False
        if str(options.get('handle')) != str(self.TC_INGRESS_FILTER_HANDLE):
            return False
        for action in options.get('actions', []):
            if (action.get('kind') == 'mirred' and
                    action.get('mirred_action') == 'redirect' and
                    action.get('direction') == 'egress' and
                    action.get('to_dev') == ifb):
                return True
        return False

    def _reserved_ingress_filters(self, filters):
        return [
            traffic_filter for traffic_filter in filters
            if traffic_filter.get('pref') == self.TC_INGRESS_FILTER_PRIORITY
        ]

    @staticmethod
    def _filter_redirects_to(traffic_filter, interface):
        options = traffic_filter.get('options')
        if not isinstance(options, dict):
            return False
        return any(
            action.get('kind') == 'mirred' and
            action.get('mirred_action') == 'redirect' and
            action.get('to_dev') == interface
            for action in options.get('actions', [])
        )

    def _root_qdisc_conflict(self, interface):
        qdisc = self._root_qdisc(interface)
        if qdisc is None or self._is_mignis_qdisc(qdisc):
            return None
        if qdisc.get('kind') == 'noqueue' and str(qdisc.get('handle')) == '0:':
            return None
        return (
            f'{interface}: existing root qdisc '
            f'{qdisc.get("kind", "unknown")} {qdisc.get("handle", "")}'.strip()
        )

    def tc_conflicts(self):
        conflicts = []
        for group in self._traffic_groups():
            interface = group['interface']
            device = group['device']
            if group['direction'] == 'ingress':
                link = self._link_info(device)
                if link is not None and not self._is_mignis_ifb(link, interface):
                    conflicts.append(
                        f'{device}: an interface with the reserved IFB name already exists')
                    continue
                if link is not None:
                    root_conflict = self._root_qdisc_conflict(device)
                    if root_conflict:
                        conflicts.append(root_conflict)

                ingress_qdisc = self._ingress_qdisc(interface)
                if ingress_qdisc is not None and ingress_qdisc.get('kind') != 'clsact':
                    conflicts.append(
                        f'{interface}: existing {ingress_qdisc.get("kind")} ingress qdisc')
                    continue

                if ingress_qdisc is not None:
                    reserved = self._reserved_ingress_filters(
                        self._ingress_filters(interface))
                    detailed = [
                        traffic_filter for traffic_filter in reserved
                        if isinstance(traffic_filter.get('options'), dict)
                    ]
                    if reserved and (
                            not detailed or
                            not all(self._is_mignis_redirect(traffic_filter, device)
                                    for traffic_filter in detailed)):
                        conflicts.append(
                            f'{interface}: ingress filter priority '
                            f'{self.TC_INGRESS_FILTER_PRIORITY} is already in use')
            else:
                root_conflict = self._root_qdisc_conflict(device)
                if root_conflict:
                    conflicts.append(root_conflict)
        return conflicts

    def _prepare_ingress(self, previous_ingress):
        prepared = {}
        for group in self._traffic_groups('ingress'):
            interface = group['interface']
            ifb = group['device']
            previous = previous_ingress.get(interface)
            if previous is not None and previous.get('ifb') != ifb:
                previous = None

            link = self._link_info(ifb)
            if link is None:
                self.execute(['ip', 'link', 'add', 'name', ifb, 'type', 'ifb'])
                self.execute(
                    ['ip', 'link', 'set', 'dev', ifb, 'alias',
                     self._ifb_alias(interface)])
            elif not self._is_mignis_ifb(link, interface):
                raise MignisException(
                    self,
                    f'Refusing to reuse interface "{ifb}": it is not the '
                    f'Mignis IFB for "{interface}".')
            self.execute(['ip', 'link', 'set', 'dev', ifb, 'up'])

            owns_clsact = (
                previous.get('owns_clsact', False)
                if previous is not None else False
            )
            ingress_qdisc = self._ingress_qdisc(interface)
            if ingress_qdisc is not None and ingress_qdisc.get('kind') == 'ingress':
                self.execute(['tc', 'qdisc', 'del', 'dev', interface, 'ingress'])
                ingress_qdisc = None
                owns_clsact = False
            if ingress_qdisc is None:
                self.execute(['tc', 'qdisc', 'add', 'dev', interface, 'clsact'])
                owns_clsact = True

            reserved = self._reserved_ingress_filters(
                self._ingress_filters(interface))
            detailed = [
                traffic_filter for traffic_filter in reserved
                if isinstance(traffic_filter.get('options'), dict)
            ]
            if detailed and all(
                    self._is_mignis_redirect(traffic_filter, ifb)
                    for traffic_filter in detailed):
                # A matchall+mirred action cannot reliably be replaced in
                # place on every iproute2/kernel combination.
                self.execute([
                    'tc', 'filter', 'del', 'dev', interface, 'ingress',
                    'protocol', 'all',
                    'priority', str(self.TC_INGRESS_FILTER_PRIORITY),
                    'handle', str(self.TC_INGRESS_FILTER_HANDLE),
                    'matchall',
                ])
            elif reserved:
                self.execute([
                    'tc', 'filter', 'del', 'dev', interface, 'ingress',
                    'priority', str(self.TC_INGRESS_FILTER_PRIORITY),
                ])

            prepared[interface] = {
                'ifb': ifb,
                'owns_clsact': owns_clsact,
            }
        return prepared

    def _cleanup_ingress(self, interface, ingress_state):
        ifb = ingress_state['ifb']
        physical_link = self._link_info(interface)
        if physical_link is not None:
            filters = self._ingress_filters(interface)
            if any(self._is_mignis_redirect(traffic_filter, ifb)
                   for traffic_filter in filters):
                self.execute([
                    'tc', 'filter', 'del', 'dev', interface, 'ingress',
                    'protocol', 'all',
                    'priority', str(self.TC_INGRESS_FILTER_PRIORITY),
                    'handle', str(self.TC_INGRESS_FILTER_HANDLE),
                    'matchall',
                ])
                filters = self._ingress_filters(interface)

            if any(self._filter_redirects_to(traffic_filter, ifb)
                   for traffic_filter in filters):
                self.warning(
                    f'Not removing IFB "{ifb}" because an ingress filter still '
                    'redirects traffic to it.')
                return False

            if ingress_state.get('owns_clsact') and not filters:
                ingress_qdisc = self._ingress_qdisc(interface)
                if ingress_qdisc is not None and ingress_qdisc.get('kind') == 'clsact':
                    self.execute(['tc', 'qdisc', 'del', 'dev', interface, 'clsact'])

        ifb_link = self._link_info(ifb)
        if ifb_link is None:
            return True
        if not self._is_mignis_ifb(ifb_link, interface):
            self.warning(
                f'Not removing interface "{ifb}" because it is no longer a '
                'Mignis-owned IFB.')
            return False
        self.execute(['ip', 'link', 'del', 'dev', ifb])
        return True

    def apply_tc_rules(self):
        '''Apply generated tc rules and remove stale Mignis-owned state.'''
        previous_state = self._load_tc_state()
        current_egress = {
            group['interface'] for group in self._traffic_groups('egress')
        }
        current_ingress = {}

        if self.tc_rules:
            current_ingress = self._prepare_ingress(previous_state['ingress'])
            shaping_devices = {
                group['device'] for group in self._traffic_groups()
            }

            # "tc qdisc replace" cannot change every existing root qdisc
            # in place (notably an existing HTB root). Remove only a root
            # carrying Mignis' reserved handle before rebuilding its tree.
            for interface in sorted(shaping_devices):
                qdisc = self._root_qdisc(interface)
                if self._is_mignis_qdisc(qdisc):
                    self.execute(['tc', 'qdisc', 'del', 'dev', interface, 'root'])

            temp_fd, temp_file = tempfile.mkstemp(suffix='.tc', prefix='mignis_')
            self.write_tc_rules(None, fd=temp_fd)
            try:
                self.execute(['tc', '-batch', temp_file])
            except MignisException as error:
                # Avoid leaving an untracked partial class tree when a later
                # command in the batch fails.
                for interface in sorted(shaping_devices):
                    try:
                        qdisc = self._root_qdisc(interface)
                        if self._is_mignis_qdisc(qdisc):
                            self.execute(['tc', 'qdisc', 'del', 'dev', interface, 'root'])
                    except MignisException as cleanup_error:
                        self.warning(
                            f'Unable to clean partial traffic shaping on '
                            f'"{interface}": {cleanup_error}')
                for interface in sorted(current_ingress):
                    try:
                        self._cleanup_ingress(
                            interface,
                            current_ingress[interface],
                        )
                    except MignisException as cleanup_error:
                        self.warning(
                            f'Unable to clean partial ingress shaping on '
                            f'"{interface}": {cleanup_error}')
                raise MignisException(
                    self,
                    str(error) +
                    f'\nThe temporary tc batch which generated the error is stored in "{temp_file}"')
            else:
                os.unlink(temp_file)

        state_to_save = {
            'egress': set(current_egress),
            'ingress': dict(current_ingress),
        }
        for interface in sorted(previous_state['egress'] - current_egress):
            try:
                qdisc = self._root_qdisc(interface)
            except MignisException as error:
                self.warning(
                    f'Unable to inspect stale traffic shaping on "{interface}": {error}')
                state_to_save['egress'].add(interface)
                continue
            if self._is_mignis_qdisc(qdisc):
                self.execute(['tc', 'qdisc', 'del', 'dev', interface, 'root'])
            elif qdisc is not None:
                self.warning(
                    f'Not removing non-Mignis root qdisc from stale interface "{interface}".')

        stale_ingress = (
            set(previous_state['ingress']) - set(current_ingress)
        )
        for interface in sorted(stale_ingress):
            ingress_state = previous_state['ingress'][interface]
            try:
                cleaned = self._cleanup_ingress(interface, ingress_state)
            except MignisException as error:
                self.warning(
                    f'Unable to clean stale ingress shaping on "{interface}": {error}')
                cleaned = False
            if not cleaned:
                state_to_save['ingress'][interface] = ingress_state

        self._save_tc_state(state_to_save)

    def apply_rules(self):
        print('\n[*] Applying rules')
        if self.dryrun:
            print('\n[*] Rules not applied (dryrun mode)')
        else:
            if self.write_rules_filename:
                output_files = self.write_all_rules(self.write_rules_filename)
                print('\n[*] Rules written to:')
                for output_file in output_files:
                    print(f'    {output_file}')
            else:
                conflicts = self.tc_conflicts()
                for conflict in conflicts:
                    self.warning('Traffic shaping conflict: ' + conflict)
                if self.force:
                    self.test_exec_rules()
                    self.apply_tc_rules()
                    print('\n[*] Rules applied.')
                else:
                    execute = ''
                    print('')
                    while execute not in ['y', 'n']:
                        if sys.version_info > (3,):
                            execute = input('Apply the rules? [y|n]: ').lower()
                        else:
                            execute = raw_input('Apply the rules? [y|n]: ').lower()
                    if execute == 'y':
                        self.test_exec_rules()
                        self.apply_tc_rules()
                        print('[*] Rules applied.')
                    else:
                        print('[!] Rules NOT applied.')

    def warning(self, s):
        if self.debug > 0:
            print("")
        print("# WARNING: " + s)

    # def reset_iptables(self):
    #    '''Netfilter reset with default ACCEPT for every chain
    #    '''
    #
    #    if not self.execute_rules:
    #        return
    #
    #    print('\n[*] Resetting netfilter')
    #    if self.dryrun:
    #        print('Skipped (dryrun mode)')
    #        return
    #
    #    reset_cmd = '''cat << EOF | iptables-restore
    #        *filter
    #        :INPUT ACCEPT
    #        :FORWARD ACCEPT
    #        :OUTPUT ACCEPT
    #        COMMIT
    #        *nat
    #        :PREROUTING ACCEPT
    #        :POSTROUTING ACCEPT
    #        :OUTPUT ACCEPT
    #        COMMIT
    #        *mangle
    #        :PREROUTING ACCEPT
    #        :INPUT ACCEPT
    #        :FORWARD ACCEPT
    #        :OUTPUT ACCEPT
    #        :POSTROUTING ACCEPT
    #        COMMIT
    #        EOF'''
    #    x = re.compile("^\s+", re.MULTILINE)
    #
    #    try:
    #        self.execute(x.sub('', reset_cmd))
    #    except MignisException as e:
    #        print('\n[!] ' + str(e))
    #        sys.exit(-3)

    def add_iptables_rule(self, r, params=None):
        if params:
            r = Rule.format_rule(r, params)
        if self.debug >= 1:
            print('iptables ' + r)
        self.iptables_rules.append(r)

    def add_tc_rule(self, rule):
        if self.debug >= 1:
            print('tc ' + rule)
        self.tc_rules.append(rule)

    @staticmethod
    def _ifb_name(interface):
        '''Return a stable, IFNAMSIZ-safe IFB name for a physical interface.'''
        digest = hashlib.sha256(interface.encode('utf-8')).hexdigest()[:10]
        return 'mifb' + digest

    @staticmethod
    def _ifb_alias(interface):
        return f'mignis-ingress:{interface}'

    def _traffic_groups(self, direction=None):
        groups = []
        for group_key in sorted(self.traffic_limit_groups):
            group = self.traffic_limit_groups[group_key]
            if direction is None or group['direction'] == direction:
                groups.append(group)
        return groups

    def traffic_control_rules(self):
        '''Generate packet marks and tc HTB classes for LIMITS rules.'''
        if not self.traffic_limit_groups:
            return

        self.wr('\n## Traffic shaping')
        egress_groups = self._traffic_groups('egress')
        if egress_groups:
            self.add_iptables_rule(f'-t mangle -N {self.TC_CHAIN}')
            self.add_iptables_rule(f'-t mangle -A POSTROUTING -j {self.TC_CHAIN}')

        # Clear only the mark bits reserved by Mignis, and only for managed
        # egress interfaces. Other fwmark users retain the lower 16 bits.
        for group in egress_groups:
            interface = group['interface']
            self.add_iptables_rule(
                f'-t mangle -A {self.TC_CHAIN} -o {interface} '
                f'-j MARK --set-xmark 0x00000000/0x{self.TC_MARK_MASK:08x}')

        for group in self._traffic_groups():
            direction = group['direction']
            interface = group['interface']
            device = group['device']
            aggregate = group['aggregate']
            flows = group['flows']

            if direction == 'ingress':
                self.add_tc_rule(
                    f'filter replace dev {interface} ingress protocol all '
                    f'priority {self.TC_INGRESS_FILTER_PRIORITY} '
                    f'handle {self.TC_INGRESS_FILTER_HANDLE} matchall '
                    f'action mirred egress redirect dev {device}')

            self.add_tc_rule(
                f'qdisc replace dev {device} root handle {self.TC_ROOT_HANDLE} '
                f'htb default {self.TC_DEFAULT_MINOR:x}')
            self.add_tc_rule(
                f'class replace dev {device} parent {self.TC_ROOT_HANDLE} '
                f'classid {self.TC_ROOT_MAJOR}:1 htb '
                f'rate {aggregate.rate} ceil {aggregate.rate}')
            self.add_tc_rule(
                f'class replace dev {device} parent {self.TC_ROOT_MAJOR}:1 '
                f'classid {self.TC_ROOT_MAJOR}:{self.TC_DEFAULT_MINOR:x} htb '
                f'rate 1kbit ceil {aggregate.rate}')
            self.add_tc_rule(
                f'qdisc replace dev {device} parent '
                f'{self.TC_ROOT_MAJOR}:{self.TC_DEFAULT_MINOR:x} '
                f'handle {self.TC_LEAF_MAJOR:x}: fq_codel')

            for index, flow_limit in enumerate(flows, start=1):
                if direction == 'egress':
                    self.add_iptables_rule(
                        f'-t mangle -A {self.TC_CHAIN} {flow_limit.iptables_match()} '
                        f'-j MARK --set-xmark '
                        f'0x{flow_limit.mark:08x}/0x{self.TC_MARK_MASK:08x}')

                class_minor = flow_limit.class_minor
                leaf_major = self.TC_LEAF_MAJOR + index
                self.add_tc_rule(
                    f'class replace dev {device} parent {self.TC_ROOT_MAJOR}:1 '
                    f'classid {self.TC_ROOT_MAJOR}:{class_minor:x} htb '
                    f'rate 1kbit ceil {flow_limit.rate}')
                self.add_tc_rule(
                    f'qdisc replace dev {device} parent '
                    f'{self.TC_ROOT_MAJOR}:{class_minor:x} '
                    f'handle {leaf_major:x}: fq_codel')
                if direction == 'egress':
                    self.add_tc_rule(
                        f'filter replace dev {device} parent {self.TC_ROOT_HANDLE} '
                        f'protocol ip priority 10 '
                        f'handle 0x{flow_limit.mark:08x}/0x{self.TC_MARK_MASK:08x} '
                        f'fw classid {self.TC_ROOT_MAJOR}:{class_minor:x}')
                else:
                    self.add_tc_rule(
                        f'filter replace dev {device} parent {self.TC_ROOT_HANDLE} '
                        f'protocol ip priority {9 + index} flower '
                        f'{flow_limit.flower_match()} '
                        f'classid {self.TC_ROOT_MAJOR}:{class_minor:x}')

        self.wr('\n##\n')

    def prune_duplicated_rules(self):
        if self.debug >= 1:
            pruned = [item for item, count in Counter(self.iptables_rules).items() if count > 1]
            if pruned:
                num_pruned = len(pruned)
                print('\n[+] Removed {:d} duplicated iptables rule{:s}:'.format(
                    num_pruned, 's' if num_pruned > 1 else ''))

                for i, rule in enumerate(pruned):
                    print('[{:d}] {:s}'.format(i + 1, rule))

        self.iptables_rules = list(OrderedDict.fromkeys(self.iptables_rules))

    def all_rules(self):
        '''Builds all rules
        '''
        print('\n[*] Building rules')
        self.policies()
        self.mandatory_rules()
        self.ignore_rules()
        if self.options['default_rules'] == 'yes':
            self.default_rules()
        self.firewall_rules()
        self.policies_rules()
        self.ip_intf_binding_rules()
        self.traffic_control_rules()
        self.custom_rules()
        if self.options['logging'] == 'yes':
            self.log_rules()
        self.prune_duplicated_rules()

    def flush_rules(self):
        self.iptables_rules = '''*filter
        :INPUT ACCEPT
        :FORWARD ACCEPT
        :OUTPUT ACCEPT
        COMMIT
        *nat
        :PREROUTING ACCEPT
        :POSTROUTING ACCEPT
        :OUTPUT ACCEPT
        COMMIT
        *mangle
        :PREROUTING ACCEPT
        :INPUT ACCEPT
        :FORWARD ACCEPT
        :OUTPUT ACCEPT
        :POSTROUTING ACCEPT
        COMMIT
        *raw
        :OUTPUT ACCEPT
        :PREROUTING ACCEPT
        COMMIT'''.split('\n')

    def mandatory_rules(self):
        '''Rules needed for the model to work.
        At this moment we only require an ESTABLISHED,RELATED
        rule on every chain in filter.
        '''
        self.wr('\n# Mandatory rules')
        self.add_iptables_rule('-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
        self.add_iptables_rule('-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
        self.add_iptables_rule('-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')

    def policies(self):
        '''Default policies for input/forward/output in filter and prerouting in mangle
        '''
        self.wr('\n# Default policies')
        self.add_iptables_rule('-P INPUT DROP')
        self.add_iptables_rule('-P FORWARD DROP')
        self.add_iptables_rule('-P OUTPUT DROP')
        self.add_iptables_rule('-t mangle -P PREROUTING DROP')

    def ignore_rules(self):
        '''Ignore rules for each interface, if specified as an option
        '''
        self.wr('\n# Ignore rules')
        for i_alias, (i_intf, i_subnet, i_options, _) in self.intf.items():
            if 'ignore' in i_options:
                self.add_iptables_rule('-A INPUT -i {0} -j ACCEPT -m comment --comment "ignore {0}"'.format(i_intf))
                self.add_iptables_rule('-A OUTPUT -o {0} -j ACCEPT -m comment --comment "ignore {0}"'.format(i_intf))
                self.add_iptables_rule('-A FORWARD -i {0} -j ACCEPT -m comment --comment "ignore {0}"'.format(i_intf))
                self.add_iptables_rule('-A FORWARD -o {0} -j ACCEPT -m comment --comment "ignore {0}"'.format(i_intf))
                self.add_iptables_rule(
                    '-t mangle -A PREROUTING -i {0} -j ACCEPT -m comment --comment "ignore {0}"'.format(i_intf))

    def default_rules(self):
        '''Default rules.
        Usually safe, they can be disabled using "default_rules no" in the configuration's options section.
        '''
        self.wr('\n# Default rules')
        # Loopback
        self.wr('# - Loopback')
        rule = 'loopback'
        self.add_iptables_rule('-A INPUT -i lo -j ACCEPT', {'abstract': rule})
        # Drop invalid packets
        self.wr('# - Invalid packets')
        rule = 'drop invalid'
        self.add_iptables_rule(
            '-t mangle -A PREROUTING -m state --state INVALID,UNTRACKED -j DROP', {'abstract': rule})
        # Allow broadcast traffic
        self.wr('# - Broadcast traffic')
        rule = 'allow broadcast traffic'
        self.add_iptables_rule('-A INPUT -d 255.255.255.255 -j ACCEPT', {'abstract': rule})
        self.add_iptables_rule('-t mangle -A PREROUTING -d 255.255.255.255 -j ACCEPT', {'abstract': rule})
        # Allow multicast traffic
        self.wr('# - Multicast traffic')
        rule = 'allow multicast traffic'
        self.add_iptables_rule('-A INPUT -d 224.0.0.0/4 -j ACCEPT', {'abstract': rule})
        self.add_iptables_rule('-t mangle -A PREROUTING -d 224.0.0.0/4 -j ACCEPT', {'abstract': rule})
        # We don't allow packets to go out from the same interface they came in
        # self.wr('# - Same-interface packets')
        # for ipsub in self.intf.keys():
        #    self.add_iptables_rule('-A FORWARD -i {intf} -o {intf} -j DROP',
        #                            {'intf': self.intf[ipsub][0], 'abstract': 'drop same-interface packets'})

    def firewall_rules(self):
        '''Execution of the firewall rules defined in section FIREWALL
        '''
        self.wr('\n\n## Rules')

        # Rules optimization
        self.fw_rulesdict = self.pre_optimize_rules(self.fw_rulesdict)

        # Cycle over the dictionary using a specific order (deny rules are first)
        # and add them to iptables
        for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
            for rule in self.fw_rulesdict[ruletype]:
                # Debugging info
                if self.debug >= 2:
                    print('\n# [D]\n' + str(rule))
                if self.debug >= 1:
                    print('\n# ' + rule.params['abstract'])
                # Add the rule to iptables
                rules = rule.get_iptables_rules(self.fw_rulesdict)
                for r in rules:
                    self.add_iptables_rule(r)

        # Check if rules overlap
        for (ruletype_a, rules_a) in self.fw_rulesdict.items():
            if ruletype_a == '!':
                continue
            for rule_a in rules_a:
                for (ruletype_b, rules_b) in self.fw_rulesdict.items():
                    if ruletype_b == '!':
                        continue
                    for rule_b in rules_b:
                        if rule_b is rule_a:
                            continue
                        # Check if rule_a and rule_b overlap
                        if rule_b.overlaps(rule_a):
                            self.warning("Two overlapping rules have been defined:\n- {0}\n- {1}\n"
                                         .format(rule_a.params['abstract'], rule_b.params['abstract']))

        self.wr('\n##\n')

    def policies_rules(self):
        '''Execution of the policies rules defined in section POLICIES
        '''
        self.wr('\n## Policies')

        # Rules optimization
        self.policies_rulesdict = self.pre_optimize_rules(self.policies_rulesdict)

        # Cycle over the dictionary and add the rules to iptables
        for ruletype in self.policies_rulesdict.keys():
            for rule in self.policies_rulesdict[ruletype]:
                # Debugging info
                if self.debug >= 2:
                    print('\n# [D]\n' + str(rule))
                if self.debug >= 1:
                    print('\n# ' + rule.params['abstract'])
                # Add the rule to iptables
                rules = rule.get_iptables_rules(self.policies_rulesdict)
                for r in rules:
                    self.add_iptables_rule(r)

        self.wr('\n##\n')

    def pre_optimize_rules(self, rules):
        '''Do all the requested optimizations over the rules, before they get
        formatted as iptables rules.
        "rules" is the dictionary containing lists of Rule objects.
        '''
        new_rules = {'/': [], '//': [], '>': [], '<>': [], '>S': [], '>M': [], '>D': [], '{': []}

        # No optimizations at the moment.
        for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
            for r in rules[ruletype]:
                new_rules[ruletype].append(r)

        '''
            # Remove duplicated rules and merge their abstract
                for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
                    for r in rules[ruletype]:
                        print r.get_iptables_rules(rules)
                        # If we can find a matching rule in new_rules (x), it means
                        # that the x and r are equivalent. So we merge their abstract.
                        x = next((x for x in new_rules[ruletype] if r == x), None)
                        if x:
                            # We add r's abstract to x's and we don't add r to the rules.
                            x.params['abstract'] += " || " + r.params['abstract']
                        else:
                            # The rule r is not present, so we add it.
                            new_rules[ruletype].append(r)

                return new_rules
        '''
        return new_rules

    def post_optimize_rules(self, rules):
        '''Do all the requested optimizations over the iptables rules, after
        they get formatted.
        "rules" is a list containing iptables rules as strings.
        '''
        return rules

    def ip_intf_binding_rules(self):
        '''Bind IP addresses to interfaces (mangle)
        '''
        self.wr('\n# IP/IF bind')
        allips = IPv4Network('0.0.0.0/0')
        for ipsub in self.intf.keys():
            subnet, ip, options, _ = self.intf[ipsub]
            # If the "ignore" option is set, we don't need an ip/if bind
            # since the packets are already accepted by the rules set in ignore_rules()
            if 'ignore' in options:
                continue

            # We can't force 127.0.0.0/8 on local, since packets with other
            # destinations may arrive.
            # e.g. when pinging an host which is not reachable we get a packet in mangle
            # with source and destination set as the pinged ip.
            # So we bind local to any ip, like we do for 0.0.0.0/0

            if ip == allips or ipsub == 'local':
                params = {'subnet': subnet, 'abstract': 'bind any ip to intf {0}'.format(subnet)}
                if ipsub != 'local':
                    # We exclude all the source IPs defined for the other interfaces
                    for other_ipsub in self.intf.keys():
                        # Skip if itself
                        if other_ipsub == ipsub:
                            continue
                        other_subnet, other_ip, other_options, _ = self.intf[other_ipsub]
                        # Skip if the interface has no ip
                        if other_ip is None:
                            continue
                        params['ip'] = other_ip
                        self.add_iptables_rule('-t mangle -A PREROUTING -i {subnet} -s {ip} -j DROP', params)
                # Accept rule for all other IPs
                self.add_iptables_rule('-t mangle -A PREROUTING -i {subnet} -j ACCEPT', params)
            else:
                params = {'subnet': subnet,
                          'ip': ip,
                          'abstract': 'bind ip {0} to intf {1}'.format(ip, subnet)}
                self.add_iptables_rule('-t mangle -A PREROUTING -i {subnet} -s {ip} -j ACCEPT', params)

    def custom_rules(self):
        '''Custom rules are executed verbatim.
        The only exception are aliases, which will be replaced with their
        corresponding value.
        '''
        self.wr('\n## Custom rules')

        # Compile the regular expressions for alias replacement
        regexp_alias = {}
        for alias in self.aliases.keys():
            for switch in ['-d ', '-s ', '--destination ', '--source ']:
                regexp_alias.setdefault(alias, []).append(
                    re.compile(rf'(?<={re.escape(switch)}){re.escape(alias)}(?=[^a-zA-Z0-9\-_])'))
        regexp_intf = {}
        for alias in self.intf:
            for switch in ['-i ', '-o ', '--in-interface ', '--out-interface ']:
                regexp_intf.setdefault(alias, []).append(
                    re.compile(rf'(?<={re.escape(switch)}){re.escape(alias)}(?=[^a-zA-Z0-9\-_])'))

        # For each rule, search and replace aliases recursively
        for rule in self.custom:
            replace_again = True
            while replace_again:
                replace_again = False
                for alias, val in self.aliases.items():
                    # Note: the re module, when using look-behind, requires a fixed-width pattern.
                    # The regex module allows variable-width patterns. This loop could be simplified
                    # to: rule = re.sub(r'(?<=switch){alias}(?=[^a-zA-Z0-9_-])', val, rule)
                    # when the regex module replaces re in the future.
                    for n, switch in enumerate(['-d ', '-s ', '--destination ', '--source ']):
                        new_rule = regexp_alias[alias][n].sub(val, rule)
                        if new_rule != rule:
                            replace_again = True
                            rule = new_rule
                # Search and replace interface aliases
                for alias in self.intf:
                    subnet = self.intf[alias][0]
                    for n, switch in enumerate(['-i ', '-o ', '--in-interface ', '--out-interface ']):
                        new_rule = regexp_intf[alias][n].sub(subnet, rule)
                        if new_rule != rule:
                            replace_again = True
                            rule = new_rule

            self.add_iptables_rule(rule)
        self.wr('\n##\n')

    def log_rules(self):
        '''Logging rules. We log the filter (input/output/forward) and mangle (prerouting only) tables
        '''
        self.wr('\n# Log')
        self.add_iptables_rule('-t mangle -N mangle_drop')
        for proto in ['icmp', 'udp', 'tcp']:
            self.add_iptables_rule('-t mangle -N mangle_drop_{0}'.format(proto))
            self.add_iptables_rule(
                '-t mangle -A mangle_drop_{0} -j LOG --log-prefix "MANGLE-DROP-{1} "'.format(proto, proto.upper()))
            self.add_iptables_rule('-t mangle -A mangle_drop_{0} -j DROP'.format(proto))
            self.add_iptables_rule('-t mangle -A mangle_drop -p {0} -j mangle_drop_{0}'.format(proto))
        self.add_iptables_rule('-t mangle -A mangle_drop -j LOG --log-prefix "MANGLE-DROP-UNK "')
        self.add_iptables_rule('-t mangle -A mangle_drop -j DROP')
        self.add_iptables_rule('-t mangle -A PREROUTING -j mangle_drop')

        self.add_iptables_rule('-N filter_drop')
        for proto in ['icmp', 'udp', 'tcp']:
            self.add_iptables_rule('-N filter_drop_{0}'.format(proto))
            self.add_iptables_rule('-A filter_drop_{0} -j LOG --log-prefix "DROP-{0} "'.format(proto, proto.upper()))
            self.add_iptables_rule('-A filter_drop_{0} -j DROP'.format(proto))
            self.add_iptables_rule('-A filter_drop -p {0} -j filter_drop_{0}'.format(proto))
        self.add_iptables_rule('-A filter_drop -j LOG --log-prefix "DROP-UNK "')
        self.add_iptables_rule('-A filter_drop -j DROP')
        self.add_iptables_rule('-A INPUT -j filter_drop')
        self.add_iptables_rule('-A OUTPUT -j filter_drop')
        self.add_iptables_rule('-A FORWARD -j filter_drop')

    def query_rules(self, query):
        # TODO: what about custom rules? and policies?
        self.wr('\n## Executing query "{0}"'.format(query))

        query_exp = self.expand_rule(query)
        if len(query_exp) != 1 or len(query_exp[0]) == 0:
            raise MignisException(self, 'Bad query "{0}"'.format(query))
        query_exp = query_exp[0]

        found_rules = {}
        for sides in ['from', 'to', 'dnat', 'snat']:
            found_rules[sides] = {'/': [], '//': [], '>': [], '<>': [], '>S': [], '>M': [], '>D': [], '{': []}

        query_len = len(query_exp)
        if query_len > 1:
            print('\n[*] Query:\n  {0}'.format(pprint.pformat(query_exp)))

        # If we have a list, we will loop for each item in the list
        for q_exp in query_exp:
            # Extract alias, interface and ip
            try:
                query_alias, query_interface, query_ip = Rule.expand_address(self, (q_exp, None))[:3]
            except AddressValueError:
                raise MignisException(self, 'Bad query "{0}"'.format(query))

            if query_len == 1:
                print('\n[*] Query:\n  alias: {0}\n  intf:  {1}\n  ip:    {2}'
                      .format(query_alias, query_interface, query_ip))
                print('\n[*] Results')

            # For each rule, check if it involves query and print the collapsed version of the rule
            # along with the single rule.
            # It avoids writing the same collapsed rule multiple times.
            for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
                for rule in self.fw_rulesdict[ruletype]:
                    abstract_collapsed = rule.params['abstract_collapsed']
                    # abstract = rule.params['abstract']
                    involve_check, involves = rule.involves(query_alias, query_interface, query_ip)
                    for side, inv in involves.items():
                        if not inv:
                            continue
                        if abstract_collapsed in found_rules[side][ruletype]:
                            continue

                        if ruletype == '{':
                            # Insert in sequence order
                            found_rules[side][ruletype].append(abstract_collapsed)
                        else:
                            # Insert sorted
                            bisect.insort(found_rules[side][ruletype], abstract_collapsed)

        for side, rules in found_rules.items():
            has_rules_side = any(map(len, rules.values()))
            if has_rules_side:
                print('\n#### {0}'.format(side).upper())
            for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
                has_rules = len(rules[ruletype])
                if has_rules:
                    print('\n## {0}:'.format(Rule.ruletype_str(ruletype)))
                for rule in rules[ruletype]:
                    print(rule)
                if has_rules:
                    print('##')
            if has_rules_side:
                print('\n####')

        # TODO: do queries with rules too, so you can check if mypc > * overlaps with any rule
        # and see all the rules that are involeved in mypc going out in any interface

        # Rule.ip_isinside(query, rule)
        # q_rulesdict = self.read_mignis_rules([[query]])

        # Check if rules overlap
        # for (ruletype_a, rules_a) in q_rulesdict.items():
        #    if ruletype_a == '/': continue
        #    for rule_a in rules_a:
        #        for (ruletype_b, rules_b) in self.fw_rulesdict.items():
        #            if ruletype_b == '/': continue
        #            for rule_b in rules_b:
        #                if rule_b is rule_a: continue
        #                # Check if rule_a and rule_b overlap
        #                if rule_b.overlaps(rule_a):
        #                    print(rule_b.params['abstract'])

        self.wr('##')

    def config_get(self, what, config, split_separator=r'\s+', split_count=0, split=True, required=True):
        '''Read a configuration section. 'what' is the configuration section name,
        while 'config' is the whole configuration as a string.
        Returns a list where each element is a line, and every element is a list
        containing the line splitted by 'split_separator'.
        '''
        if what not in config:
            if required:
                raise MignisConfigException(f'Missing section "{what}" in the configuration file.')
            return []

        r = re.search(r'(.*?)(\n*\Z)', config[what], re.DOTALL)
        if r and r.groups():
            # Get the section contents and split by line
            r = r.groups()[0].strip().split('\n')
            # Remove comments and empty lines
            r = filter(lambda x: x and x[0] != '#', r)
            if split:
                # Split each line by separator (maxsplit as keyword argument)
                r = list(map(lambda x: list(map(lambda x: x.strip(), re.split(split_separator, x, maxsplit=split_count))), r))
            return r
        else:
            return None

    def _resolve_traffic_limit_address(
            self, value: str) -> Optional[Union[IPv4Address, IPv4Network]]:
        '''Resolve a LIMITS address to an IPv4 host/network, or None for "*".'''
        if value == '*':
            return None

        if value == 'local':
            raise MignisConfigException(
                'The special "local" alias is not supported in LIMITS selectors; '
                'use a concrete local IPv4 address instead.')

        if value in self.intf:
            subnet = self.intf[value][1]
            if subnet is None:
                raise MignisConfigException(
                    f'Interface alias "{value}" has no subnet and cannot be used in a traffic selector.')
            return subnet

        visited = set()
        resolved = value
        while resolved in self.aliases:
            if resolved in visited:
                raise MignisConfigException(
                    f'Alias cycle found while resolving traffic selector "{value}".')
            visited.add(resolved)
            resolved = self.aliases[resolved]

        if any(character in resolved for character in '(),:'):
            raise MignisConfigException(
                f'Traffic selector "{value}" must resolve to one IPv4 address or subnet.')

        try:
            if '/' in resolved:
                return IPv4Network(resolved, strict=True)
            return IPv4Address(resolved)
        except ValueError:
            raise MignisConfigException(
                f'Invalid IPv4 address, subnet or alias "{value}" in LIMITS.')

    def read_traffic_limits(self, config):
        '''Parse and validate the optional LIMITS section.

        Syntax:
            on INTERFACE [egress|ingress] FROM > TO RATE

        The direction defaults to egress for backward compatibility. A
        catch-all "* > *" rule is required as the aggregate rate for every
        shaped interface and direction.
        '''
        raw_limits = self.config_get('LIMITS', config, split=False, required=False)
        limits = []

        for raw_limit in raw_limits:
            parts = raw_limit.split()
            if len(parts) == 6 and parts[0].lower() == 'on' and parts[3] == '>':
                direction = 'egress'
                _, interface_alias, source_text, _, destination_text, rate = parts
            elif (len(parts) == 7 and parts[0].lower() == 'on' and
                  parts[2].lower() in ('egress', 'ingress') and parts[4] == '>'):
                direction = parts[2].lower()
                _, interface_alias, _, source_text, _, destination_text, rate = parts
            else:
                raise MignisConfigException(
                    f'Bad traffic limit "{raw_limit}". '
                    'Expected: on INTERFACE [egress|ingress] FROM > TO RATE')

            if interface_alias not in self.intf:
                raise MignisConfigException(
                    f'Unknown interface alias "{interface_alias}" in traffic limit "{raw_limit}".')

            interface = self.intf[interface_alias][0]
            if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', interface):
                raise MignisConfigException(
                    f'Interface name "{interface}" cannot be safely used with tc.')

            source = self._resolve_traffic_limit_address(source_text)
            destination = self._resolve_traffic_limit_address(destination_text)
            limits.append(TrafficLimit(
                interface_alias,
                interface,
                source,
                destination,
                source_text,
                destination_text,
                rate,
                raw_limit,
                direction,
            ))

        groups = {}
        for limit in limits:
            groups.setdefault((limit.direction, limit.interface), []).append(limit)

        validated_limits = []
        ifb_interfaces = {}
        for group_key in sorted(groups):
            direction, interface = group_key
            interface_limits = groups[group_key]
            aggregate_limits = [limit for limit in interface_limits if limit.is_interface_limit]
            flow_limits = [limit for limit in interface_limits if not limit.is_interface_limit]

            if len(aggregate_limits) != 1:
                if not aggregate_limits:
                    raise MignisConfigException(
                        f'Interface "{interface}" has flow-specific {direction} traffic limits '
                        'but no aggregate "* > *" limit in the same direction.')
                raise MignisConfigException(
                    f'Interface "{interface}" has more than one aggregate {direction} '
                    'traffic limit.')

            aggregate = aggregate_limits[0]
            for flow_limit in flow_limits:
                if flow_limit.rate_bps > aggregate.rate_bps:
                    raise MignisConfigException(
                        f'Traffic limit "{flow_limit.abstract}" exceeds the aggregate '
                        f'interface rate {aggregate.rate}.')

            for index, flow_limit in enumerate(flow_limits):
                for other in flow_limits[index + 1:]:
                    if flow_limit.overlaps(other):
                        raise MignisConfigException(
                            'Overlapping traffic limits are ambiguous:\n'
                            f'- {flow_limit.abstract}\n'
                            f'- {other.abstract}')

            flow_limits.sort(key=lambda limit: limit.sort_key())
            max_flow_count = min(
                0xffff - self.TC_FIRST_FLOW_MINOR,
                0xffff - self.TC_LEAF_MAJOR,
            )
            if len(flow_limits) > max_flow_count:
                raise MignisConfigException(
                    f'Too many traffic limits on interface "{interface}".')

            for index, flow_limit in enumerate(flow_limits):
                flow_limit.class_minor = self.TC_FIRST_FLOW_MINOR + index
                if direction == 'egress':
                    flow_limit.mark = flow_limit.class_minor << self.TC_MARK_SHIFT

            shaping_interface = interface
            if direction == 'ingress':
                shaping_interface = self._ifb_name(interface)
                previous_interface = ifb_interfaces.get(shaping_interface)
                if previous_interface is not None and previous_interface != interface:
                    raise MignisConfigException(
                        f'Unable to allocate distinct IFB interfaces for "{previous_interface}" '
                        f'and "{interface}".')
                ifb_interfaces[shaping_interface] = interface

            groups[group_key] = {
                'direction': direction,
                'interface': interface,
                'device': shaping_interface,
                'aggregate': aggregate,
                'flows': flow_limits,
            }
            validated_limits.append(aggregate)
            validated_limits.extend(flow_limits)

        self.traffic_limits = validated_limits
        self.traffic_limit_groups = groups

    def config_split_ipport(self, s):
        '''Split an address in the form [ip|interface_alias]:port1[-port2]
        and returns a list in the form [ip or interface_alias, [port1, port2]]
        '''
        if not s:
            return s

        # Split ip and ports
        r = s.split(':')
        if len(r) > 2:
            raise MignisConfigException('invalid host:port parameter "{0}".'.format(s))

        # Convert aliases
        # if r[0] in self.aliases:
        #    r[0] = self.aliases[r[0]]

        # Ports
        if len(r) == 1:
            r.append(None)
        else:
            ports = list(map(int, r[1].split('-')))
            if (len(ports) > 2 or
                    ports[0] < 0 or ports[0] > 65535 or
                    (len(ports) == 2 and (ports[1] < 0 or ports[1] > 65535 or ports[0] > ports[1]))):
                raise MignisConfigException('invalid port range "{0}".'.format(ports))
            r[1] = ports
        return r

    def expand_rule(self, rule):
        # Convert aliases
        # TODO: this is truly ugly. Do a better replacement for aliases
        replace_again = True
        while replace_again:
            replace_again = False
            for alias, val in self.aliases.items():
                new_rule = self.alias_regexp[alias].sub(val, ' ' + rule + ' ')[1:-1]
                if new_rule != rule:
                    replace_again = True
                    rule = new_rule

        # Create a list of lists, splitting on ", *" for each list found.
        # Each list is written using "(item1, item2, ...)".
        rules = list(map(lambda x: re.split(r', *', x), filter(None, re.split(r'[()]', rule))))

        # Flatten lists of lists
        # there is a list of lists if an the first or last element of an inner list is ''
        i = 0
        while i < len(rules):
            if rules[i][-1] == '':
                rules[i] = rules[i][:-1]
                if rules[i + 1]:
                    rules[i] += rules.pop(i + 1)
            elif rules[i][0] == '':
                rules[i - 1] += rules.pop(i)[1:]
            else:
                i += 1

        return rules

    def read_mignis_rules(self, abstract_rules):
        rulesdict = {'/': [], '//': [], '>': [], '<>': [], '>S': [], '>M': [], '>D': [], '{': []}

        # Expand lists inside each abstract_rule and add each expanded rule
        # (at the moment we don't expand params)
        inside_sequence = False
        for abstract_rule in abstract_rules:
            if abstract_rule[0] == '{':
                if inside_sequence:
                    raise MignisConfigException('Nested sequences are meaningless.')
                inside_sequence = True
                continue
            elif abstract_rule[0] == '}':
                if not inside_sequence:
                    raise MignisConfigException('Unexpected end of sequence "}" found.')
                inside_sequence = False
                continue

            rule = abstract_rule[0]
            params = abstract_rule[1] if len(abstract_rule) > 1 else ''

            if self.debug >= 3:
                print('Expanding rule {0}'.format(abstract_rule))

            rules = self.expand_rule(rule)

            # Add each expanded rule
            abstract_rule_collapsed = ' '.join(abstract_rule)
            for rule in product(*rules):
                rule = ''.join(rule)

                # Replace known strings with aliases, for the abstract rule
                abstract_rule = rule
                for alias, val in self.aliases.items():
                    abstract_rule = self.inverse_alias_regexp[val].sub(alias, ' ' + abstract_rule + ' ')[1:-1]
                abstract_rule = (abstract_rule + ' ' + params).strip()

                if self.debug >= 3:
                    print("    expanded rule: {0}".format([abstract_rule, params]))

                # rule = re.search('^(.*?) *(\[.*?\])? (/|//|>|<>) (\[.*?\])? *(.*?)$', rule)
                rule = self.rule_regexp.search(rule)
                if not rule:
                    raise MignisConfigException('bad firewall rule "{0}".'.format(rule))
                rule = rule.groups()

                (r_from, r_nat_left, ruletype, r_nat_right, r_to, protocol) = rule

                r_from = self.config_split_ipport(r_from)
                r_to = self.config_split_ipport(r_to)

                # Find and replace aliases inside params
                if params:
                    for alias, val in self.aliases.items():
                        params = self.alias_regexp[alias].sub(val, ' ' + params + ' ')[1:-1]

                try:
                    r = []
                    if ruletype in ['/', '//']:
                        # Deny
                        r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                      ruletype, r_from, r_to, protocol, params, None))
                    elif ruletype == '<>':
                        # Bidirectional forward
                        r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                      ruletype, r_from, r_to, protocol, params, None))
                    elif ruletype == '>':
                        # if r_nat_left and r_nat_right:
                        #     raise MignisConfigException('bad firewall rule in configuration file.')
                        if r_nat_left:
                            # SNAT
                            if r_nat_left == '[.]':
                                # Masquerade
                                ruletype = '>M'
                                r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                              ruletype, r_from, r_to, protocol, params, None))
                            else:
                                # Classic SNAT
                                ruletype = '>S'
                                nat = self.config_split_ipport(r_nat_left[1:-1])
                                r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                              ruletype, r_from, r_to, protocol, params, nat))
                        if r_nat_right:
                            # DNAT
                            ruletype = '>D'
                            nat = self.config_split_ipport(r_nat_right[1:-1])
                            r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                          ruletype, r_from, r_to, protocol, params, nat))
                        # we have no DNAT *and* no SNAT
                        elif not r_nat_left:
                            # Forward
                            r.append(Rule(self, abstract_rule, abstract_rule_collapsed,
                                          ruletype, r_from, r_to, protocol, params, None))
                    else:
                        raise MignisConfigException('bad firewall rule in configuration file.')
                except RuleException as e:
                    raise MignisConfigException(str(e))

                if inside_sequence:
                    rulesdict['{'] += r
                else:
                    rulesdict[ruletype] += r

        if self.debug >= 2:
            pprint.pprint(rulesdict, width=200)

        return rulesdict

    def config_include(self, match):
        filename = match.groups()[0]
        if not filename:
            raise MignisConfigException('Invalid include directive "{0}".'.format(match.group()))

        filename = self.config_dir + '/' + filename
        try:
            with open(filename) as included_file:
                return included_file.read().strip()
        except OSError:
            raise MignisConfigException('Unable to read file "{0}" for inclusion.'.format(filename))

    def read_config(self):
        '''Parses the configuration file and populates the rulesdict dictionary
        '''
        try:
            print("[*] Reading the configuration")
            self.config_dir = os.path.dirname(self.config_file)
            with open(self.config_file) as config_file:
                config = config_file.read()

            # Execute the @include directives (recursively)
            old_config = ''
            while config != old_config:
                old_config = config
                config = re.sub(r'(?<=\n)@include[ \t]+(.*?)(?=\n)', self.config_include, config)

            # Replace every sequence of tabs and spaces with a single space
            config = re.sub(r'[ \t]+', ' ', config)

            # Split by section
            config = re.split(r'(OPTIONS|INTERFACES|ALIASES|FIREWALL|POLICIES|LIMITS|CUSTOM)\n', config)[1:]
            config = dict(zip(config[::2], config[1::2]))

            # Read the options
            options = self.config_get('OPTIONS', config)
            # Convert to lowercase and to a dictionary
            options = dict([[y.lower() for y in x] for x in options])
            # Setting default values
            default_options = {'default_rules': 'yes', 'logging': 'yes'}
            self.options = dict(default_options, **options)

            # Read the interfaces
            intf = self.config_get('INTERFACES', config)
            for x in list(intf):
                if len(x) < 3:
                    raise MignisConfigException('Bad interface declaration "{0}".'.format(' '.join(x)))
                intf_alias, intf_name, intf_subnet = x[:3]
                intf_options = x[3:] if len(x) >= 4 else []
                intf_subnet = None if intf_subnet == 'none' else IPv4Network(intf_subnet, strict=True)
                # Extract pub=IP option (public IP for NAT reflection behind double NAT)
                pub_ip = None
                for opt in intf_options:
                    if opt.startswith('pub='):
                        pub_ip = IPv4Address(opt[4:])
                        intf_options.remove(opt)
                        break
                self.intf[intf_alias] = (intf_name, intf_subnet, intf_options, pub_ip)
            self.intf['local'] = ('lo', IPv4Network('127.0.0.0/8', strict=True), [], None)

            # Read the aliases
            aliases_list = self.config_get('ALIASES', config, split_count=1)
            self.aliases = {}
            for x in aliases_list:
                self.aliases[x[0]] = x[1]

            # Compile aliases regexp for replacement in rules
            self.alias_regexp = {}
            for alias, val in self.aliases.items():
                # Match alias when surrounded by non-alphanumeric characters
                self.alias_regexp[alias] = re.compile(rf'(?<=[^a-zA-Z0-9\-_]){re.escape(alias)}(?=[^a-zA-Z0-9\-_])')

            self.inverse_alias_regexp = {}
            for alias, val in self.aliases.items():
                # Match value when surrounded by non-alphanumeric characters (for inverse replacement)
                self.inverse_alias_regexp[val] = re.compile(rf'(?<=[^a-zA-Z0-9\-_]){re.escape(val)}(?=[^a-zA-Z0-9\-_])')

            # Read the optional traffic shaping rules.
            self.read_traffic_limits(config)

            # Compile the rules regexp
            allowed_chars = r'[a-zA-Z0-9\./\*_\-:,\(\) ]'
            self.rule_regexp = re.compile(
                rf'^({allowed_chars}+?)(?: +(\[{allowed_chars}+?\]))? +(/|//|>|<>) +(?:(\[{allowed_chars}+?\])'
                rf' +)?({allowed_chars}*?)(?: +({allowed_chars}*?))?$')

            # Read the firewall rules
            if self.debug >= 2:
                print("\n[+] Firewall rules")
            abstract_rules = self.config_get('FIREWALL', config, r'\|', 1)
            self.fw_rulesdict = self.read_mignis_rules(abstract_rules)

            # Read the default policies
            policies = self.config_get('POLICIES', config, r'\|', 1)
            if self.debug >= 2:
                print("\n[+] Policies")
            self.policies_rulesdict = self.read_mignis_rules(policies)
            # Verify that only reject and drop rules were specified
            for k, item in self.policies_rulesdict.items():
                if k not in ['/', '//'] and item != []:
                    raise MignisConfigException('You can only specify reject (//) or drop (/) rules as policies.')

            # Read the custom rules
            self.custom = self.config_get('CUSTOM', config, split=False)
        except MignisConfigException as e:
            raise MignisException(self, 'Error in configuration file:\n' + str(e))

# Argument parsing


def parse_args():
    '''Argument parsing
    '''
    parser = argparse.ArgumentParser(description='A semantic based tool for firewall configuration',
                                     add_help=False)
    parser.add_argument('--help', '-h', action='help', help='show this help message and exit')
    action_group = parser.add_argument_group('possible actions:')
    action_group.add_argument('-F', '--flush', dest='flush',
                              help='flush iptables ruleset and Mignis traffic shaping',
                              required=False, action='store_true')
    action_group.add_argument('-c', '--config', dest='config_file', metavar='filename',
                              help='read mignis rules from file', required=False)
    config_group = parser.add_argument_group('options for --config/-c')
    config_group = config_group.add_mutually_exclusive_group(required=False)
    config_group.add_argument('-w', '--write', dest='write_rules_filename', metavar='filename',
                              help='write rules to file (plus .tc/.tc.sh when shaping)',
                              required=False)
    config_group.add_argument('-e', '--execute', dest='execute_rules', 
                              help='execute the rules without writing to file', required=False, 
                              action='store_true')
    config_group.add_argument('-q', '--query', dest='query_rules', metavar='query',
                              help='perform a query over the configuration (unstable)', required=False)
    parser.add_argument('-d', '--debug', dest='debug', help='set debugging output level (0-2)',
                        required=False, type=int, default=0, choices=range(4))
    parser.add_argument('-n', '--dryrun', dest='dryrun', help='do not execute/write the rules (dryrun)',
                        required=False, action='store_true')
    parser.add_argument('-f', '--force', dest='force', help='force rule execution or writing',
                        required=False, action='store_true')
    # parser.add_argument('-r', dest='reset_script', help='reset script to execute when an error occurs', required=False)
    args = vars(parser.parse_args())
    if args['config_file'] and args['flush']:
        parser.error('argument -F/--flush: not allowed with argument -c/--config')
    elif not args['config_file'] and not args['flush']:
        parser.error('error: one of the arguments -F/--flush -c/--config is required')
    if args['config_file'] and not any((args['write_rules_filename'], args['execute_rules'], args['query_rules'])):
        parser.error('error: one of the arguments -w/--write -e/--execute -q/--query is required')
    return args


def main():
    args = parse_args()

    try:
        mignis = Mignis(args['config_file'], args['debug'], args['force'], args['dryrun'], 
            args['write_rules_filename'], args['execute_rules'], args['flush'])

        if args['query_rules']:
            mignis.query_rules(args['query_rules'])
        else:
            mignis.all_rules()
            mignis.apply_rules()
    except MignisException as e:
        print('\n[!] ' + str(e))
        sys.exit(-1)
    except:
        print('\n[!] An unexpected error occurred!')
        traceback.print_exc()
        sys.exit(-2)

    print('\n[*] Done.')


if __name__ == '__main__':
    main()
