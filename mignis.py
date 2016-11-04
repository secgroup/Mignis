#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
mignis.py is a semantic based tool for firewall configuration.
For usage instructions type:
$ ./mignis.py -h
'''

import re
import sys
from ipaddr import IPv4Address, IPv4Network, AddressValueError
from ipaddr_ext import IPv4Range
import os
import pprint
import argparse
import traceback
import string
from itertools import product
from collections import defaultdict
import tempfile
import bisect
import copy


try:
    iteritems = dict.iteritems
    iterkeys = dict.iterkeys
    stdin = raw_input
except (NameError, AttributeError):  # py3
    iteritems = dict.items
    iterkeys = dict.keys
    stdin = input


class RuleException(Exception):
    pass


class Rule:
    # Reference to the Mignis object
    mignis = None
    # Dictionary with rule parameters
    params = {}

    def __init__(self, mignis, abstract_rule, abstract_rule_collapsed, ruletype, r_from, r_to, protocol, filters, nat):
        self.mignis = mignis

        if filters is None:
            filters = ''

        # Sanitize filters
        self._check_filters(filters)

        # Expand r_from, r_to and r_nat to aliases, interfaces, IPs and ports
        # from_alias, from_intf, from_ip, from_port = self.expand_address(mignis, r_from)
        exp_from = self.expand_address(mignis, r_from)
        exp_to = self.expand_address(mignis, r_to)
        exp_nat = self.expand_address(mignis, nat) if nat else {}

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
            'from': exp_from,
            'to': exp_to,
            # NAT options
            'nat': exp_nat,
        }

        if (self.is_snat() or self.is_dnat()) and not nat:
            raise MignisException(mignis,
                                  "Rule {} should be {} but hasn't any nat address specified"
                                  .format(abstract_rule, ruletype)
                                  )

    def __repr__(self):
        return pprint.pformat(self.params)

    @staticmethod
    def ruletype_str(ruletype):
        if ruletype == '/': return 'Drop'
        elif ruletype == '//': return 'Reject'
        elif ruletype == '<>': return 'Forward (bidirectional)'
        elif ruletype == '>': return 'Forward'
        elif ruletype == '>D': return 'Destination Nat'
        elif ruletype == '>M': return 'Masquerade'
        elif ruletype == '>S': return 'Source Nat'
        elif ruletype == '{': return 'Sequence'
        else: raise RuleException('Invalid ruletype.')

    def _check_filters(self, filters):
        '''Verify that some options are not used inside filters.
        At the moment we look for:
        --dport, --dports, --destination-port, --destination-ports,
        --sport, --sports, --source-port, --source-ports,
        -s, --source, -d, --destination,
        -p, --protocol,
        -j, -C, -S, -F, -L, -Z, -N, -X, -P, -E
        '''
        check_regexp = ('( |\A)('
                        '--dport|--dports|--destination-port|--destination-ports|'
                        '--sport|--sports|--source-port|--source-ports'
                        ')( |\Z)')
        invalid_option = re.search(check_regexp, filters)
        if invalid_option:
            raise RuleException('Invalid filter specified: {0}.\n'
                                'You have to use the Mignis\'s syntax to specify ports.'
                                .format(invalid_option.groups()[1]))
        check_regexp = ('( |\A)('
                        # '-s|--source|-d|--destination|'
                        '-p|--protocol|'
                        '-j|-C|-S|-F|-L|-Z|-N|-X|-P|-E'
                        ')( |\Z)')
        invalid_option = re.search(check_regexp, filters)
        if invalid_option:
            raise RuleException('Invalid filter specified: {0}.\n'
                                'You can\'t use this switch as a filter.'
                                .format(invalid_option.groups()[1]))

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
    def expand_address(mignis, addr):
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
            # ip = mignis.intf[ipsub][1]
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
                    raise MignisException(mignis, 'The IP address "{0}" does not belong to any subnet.'.format(ipsub))
                intf = mignis.intf[alias][0]
        return {
            "alias": alias,
            "intf": intf,
            "ip": ip,
            "port": port,
        }

    @staticmethod
    def ip2subnet(mignis, ip):
        '''Returns the alias of the subnet the ip is in, or None if not found
        '''
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

    def _format_intfip(self, direction, params, iponly=False, portonly=False):
        '''Given 'srcdst' (which specifies if we want a source (s) or destination (d) filter type),
        converts the given address (which may be any of: alias, interface, ip, port) to a string ready for filtering in
        the form '-[io] intf -[ds] ip --[sd]port port'.
        The address is get by using '<direction>_ip', where direction can be any of 'from', 'to' or 'nat'.
        If iponly is specified, an IP address is returned instead of an interface.
        If portonly is specified, no interface/ip filters are added.
        '''
        intf_alias = 'alias'
        intf = 'intf'
        ip = 'ip'
        port = 'port'

        intfip = {
            ip: None,
            intf: None,
            port: None,
        }
        if not portonly:
            if params[direction][ip]:
                # If there is an IP, we use that instead of the interface as it's more specific
                ip_addr = params[direction][ip]
                intfip[ip] = ip_addr
            elif iponly:
                # We need to return an IP address instead of the interface,
                # but since no IP was explicitly specified, we have to return the subnet
                if params[direction][intf_alias]:
                    alias = params[direction][intf_alias]
                    subnet = self.mignis.intf[alias][1]
                    intfip[ip] = subnet
            elif params[direction][intf]:
                # If there is no IP, we use the interface
                intfip[intf] = copy.deepcopy(params[direction][intf])
                # If there is no IP or interface, we don't add any filter

        if params[direction][port]:
            r_port = params[direction][port]
            intfip[port] = r_port

        return intfip

    def get_rules(self, rulesdict):
        params = copy.deepcopy(self.params)

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
            raise RuleException('Key error: invalid rule type \'{0}\'.'.format(self.params['rtype']))

    @staticmethod
    def ip_isinside(a, b):
        '''Returns True if a is inside b.
        a and b can be either None, IPv4Address, IPv4Range or IPv4Network.
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
    def ip_equals(a, b):
        '''Returns True if a is equal to b.
        a and b can be either None, IPv4Address, IPv4Range or IPv4Network.
        '''
        if b is None:
            return a is None
        if a is None:
            # b is not None, while a is
            return False
        return type(a) == type(b) and a == b

    @staticmethod
    def port_isinside(a, b):
        '''Returns True if the port range a is inside b.
        a and b can be either None, or a list/tuple of maximum length 2.
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
                return b[0] <= a[0] <= b[1]
            else:
                # a is a range
                return a[0] >= b[0] and a[1] <= b[1]

    @staticmethod
    def port_equals(a, b):
        '''Returns True if the port range a is equal b.
        a and b can be either None, or a list/tuple of maximum length 2.
        '''
        if b is None:
            return a is None
        if a is None:
            # b is not None, while a is
            return False
        if len(b) == 1:
            # b is a port
            if len(a) == 1:
                # a is a port
                return a[0] == b[0]
            else:
                # a is a range, but maybe it's like 80-80
                return a[0] == a[1] == b[0]
        else:
            # b is a range
            if len(a) == 1:
                # a is a port
                return False
            else:
                # a is a range
                return a[0] == b[0] and a[1] == b[1]

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
        if not ((params_b['from']['intf'] is None or params_a['from']['intf'] == params_b['from']['intf']) and
                (params_b['to']['intf'] is None or params_a['to']['intf'] == params_b['to']['intf'])):
            return False

        # Check if from_ip and to_ip of a are subset of, respectively, from_ip and to_ip of b
        if not (Rule.ip_isinside(params_a['from']['ip'], params_b['from']['ip']) and
                Rule.ip_isinside(params_a['to']['ip'], params_b['to']['ip'])):
            return False

        # Do the same for ports
        if not (Rule.port_isinside(params_a['from']['port'], params_b['from']['port']) and
                Rule.port_isinside(params_a['to']['port'], params_b['to']['port'])):
            return False

        # Do the same for protocols
        protocol_a = params_a['protocol']
        protocol_b = params_b['protocol']
        if not (protocol_a == protocol_b or protocol_a == 'all' or protocol_b == 'all'):
            return False

        # Check if nat overlaps
        # TODO: do this

        return True

    def involves(self, alias, interface, ip):
        '''Given an alias, interface and ip
        check if it is involved in the rule.
        '''

        def check_involves(x):
            return (
                (interface == self.params[x]['intf'] or
                 None in [interface, self.params[x]['intf']]
                ) and
                (Rule.ip_isinside(ip, self.params[x]['ip']) or
                 Rule.ip_isinside(self.params[x]['ip'], ip) or
                 None in [ip, self.params[x]['ip']]
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

        return any(checks.values()), checks

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
    def get_protocols(params):
        # TODO merge functionality of protocols inside rules checkings
        '''Add the protocol to the rule.
        We need to add this before adding the --[ds]port switch as
        iptables won't recognize the -p switch if placed after --dport.
        '''
        # We add the protocol if a port or protocol have been specified.
        # print("[get_protocols]: "+str(params))
        port = (params.get('destination', {}).get('port', False) or
                params.get('source', {}).get('port', False) or
                params.get('nat', {}).get('port', False))

        protocols = []
        if 'protocol' in params and params['protocol']:
            protocols.append(params['protocol'])
        protocols.extend(params.get('protocols', []))

        if port and not protocols:
            # If a port has been specified without a protocol, add a keyword 'all' protocol.
            protocols.append('all')
        return protocols

    def _forward(self, params, flip=False):
        '''Translation for ">".
        If flip is True, the 'to' and 'from' parameters are switched
        (this only happens for the non-local case).
        '''
        rules = []
        if 'local' == params['from']['alias'] or 'local' == params['to']['alias']:
            # local case
            dir1 = 'from'
            dir2 = 'to'
        else:
            # forward case
            dir1 = 'to' if flip else 'from'
            dir2 = 'from' if flip else 'to'

        input_source = {}
        input_destination = {}
        output_source = {}
        output_destination = {}
        forward_source = {}
        forward_destination = {}
        if params['from']['alias'] == 'local' and 'local' == params['to']['alias']:
            # OUTPUT and INPUT rule (this is the "local > local" case)
            # TODO: we can avoid this and use the same code as 'from_alias', so by exploiting the generic
            # "established,related" rule but as we know how to do it without it, maybe it's better?
            # We should think about it.
            output_source = self._format_intfip(dir1, params, portonly=True)
            output_destination = self._format_intfip(dir2, params)
            input_source = self._format_intfip(dir2, params)
            input_destination = self._format_intfip(dir1, params, portonly=True)
        elif 'local' == params['from']['alias']:
            # OUTPUT rule
            if flip:
                input_source = self._format_intfip(dir2, params)
                input_destination = self._format_intfip(dir1, params, portonly=True)
            else:
                output_source = self._format_intfip(dir1, params, portonly=True)
                output_destination = self._format_intfip(dir2, params)
        elif 'local' == params['to']['alias']:
            # INPUT rule
            if flip:
                output_source = self._format_intfip(dir2, params, portonly=True)
                output_destination = self._format_intfip(dir1, params)
            else:
                input_source = self._format_intfip(dir1, params)
                input_destination = self._format_intfip(dir2, params, portonly=True)
        else:
            # FORWARD rule
            forward_source = self._format_intfip(dir1, params)
            forward_destination = self._format_intfip(dir2, params)
        params['targets'] = ['accept']
        if input_source:
            iparams = copy.deepcopy(params)
            iparams['source'] = input_source
            iparams['destination'] = input_destination
            rules.append(('ip', 'filter', 'input', iparams))
        if output_source:
            oparams = copy.deepcopy(params)
            oparams['source'] = output_source
            oparams['destination'] = output_destination
            rules.append(('ip', 'filter', 'output', oparams))
        if forward_source:
            fparams = copy.deepcopy(params)
            fparams['source'] = forward_source
            fparams['destination'] = forward_destination
            rules.append(('ip', 'filter', 'forward', fparams))
        return rules

    def _dbl_forward(self, params):
        '''Translation for "<>"
        '''
        rules = []
        rules.extend(self._forward(params))
        rules.extend(self._forward(params, flip=True))
        return rules

    def _forward_deny(self, params, reject=False):
        '''Translation for "/" and "//"
        '''
        rules = []
        params['target'] = 'reject' if reject else 'drop'
        if 'local' == params['from']['alias']:
            # OUTPUT rule
            # this also matches the "local / local" rule
            params['source'] = self._format_intfip('from', params, portonly=True)
            params['destination'] = self._format_intfip('to', params)
            chain = 'output'
        elif 'local' == params['to']['alias']:
            # INPUT rule
            params['source'] = self._format_intfip('from', params)
            params['destination'] = self._format_intfip('to', params, portonly=True)
            chain = 'input'
        else:
            # FORWARD rule
            params['source'] = self._format_intfip('from', params)
            params['destination'] = self._format_intfip('to', params)
            chain = 'forward'
        rules.append(('ip', 'filter', chain, params))
        return rules

    def _snat(self, params, masquerade=False):
        '''Translation for ">" in the case of a SNAT
        '''
        rules = []
        fparams = copy.deepcopy(params)
        rules.extend(self._forward(fparams))

        if masquerade:
            params['target'] = 'masquerade'
        else:
            params['snat'] = (params['nat']['ip'], params['nat']['port'] or None)
            params['target'] = 'snat'
        # TODO: if from or to are local, must be in output/input chains (hooks for nft) and be accepted on output (like dnat)
        params['source'] = self._format_intfip('from', params, iponly=True)
        params['destination'] = self._format_intfip('to', params)
        rules.append(('ip', 'nat', 'postrouting', params))
        return rules

    def _dnat(self, params):
        '''Translation for ">" in the case of a DNAT
        '''
        rules = []
        if re.search('(^| )(-m|ct) state ', params['filters']):
            self.mignis.warning('Inspectioning the state in DNAT might corrupt the rule.' +
                                'Use it only if you know what you\'re doing.\n- {0}'.format(params['abstract']))

        mparams = copy.deepcopy(params)
        mparams['source'] = self._format_intfip('from', mparams)
        mparams['destination'] = self._format_intfip('to', mparams, iponly=True)
        mparams['target'] = 'drop'
        mparams['states'] = ['new']
        rules.append(('ip', 'mangle', 'prerouting', mparams))

        # Forward rules without filters
        fparams = copy.deepcopy(params)
        fparams['filters'] = ''
        rules.extend(self._forward(fparams))

        if 'local' == params['from']['alias']:
            params['source'] = self._format_intfip('from', params, portonly=True)
            chain = 'output'
        else:
            params['source'] = self._format_intfip('from', params)
            chain = 'prerouting'

        params['destination'] = self._format_intfip('nat', params, iponly=True)
        # TODO: verify that to_ip is not None.
        params['dnat'] = (str(params['to']['ip']), params['to']['port'] or None)
        params['target'] = 'dnat'
        rules.append(('ip', 'nat', chain, params))
        return rules


class FwTables(object):
    def __init__(self, mignis):
        '''
        adds all necessary tables in-program to be considered.
        tables with no rules shouldn't be outputted in final file
        here all used tables should be defined.
        '''
        self.mignis = mignis
        self.framework = self.NFTABLES if mignis.nftables else self.IPTABLES
        self.debug = mignis.debug
        self._tables = {}
        # extra options are ignored if not nftables
        # but may be useful in iptables for further implementations/optimizations (?)
        self.add_table('filter', 'ip')
        self.add_chain('filter', 'input', typ='filter', hook='input', priority=0, policy='DROP')
        self.add_chain('filter', 'forward', typ='filter', hook='forward', priority=0, policy='DROP')
        self.add_chain('filter', 'output', typ='filter', hook='output', priority=0, policy='DROP')
        self.add_table('mangle', 'ip')
        # mangle table is used only for PREROUTING filters with iptables (before dnat),
        # so equals to a filter type prerouting chain with priority -150 in nftables
        self.add_chain('mangle', 'prerouting', typ='filter', hook='prerouting', priority=-150, policy='DROP')
        self.add_table('nat', 'ip')
        self.add_chain('nat', 'input', typ='nat', hook='input', priority=100)
        self.add_chain('nat', 'output', typ='nat', hook='output', priority=-100)
        self.add_chain('nat', 'prerouting', typ='nat', hook='prerouting', priority=-100)
        self.add_chain('nat', 'postrouting', typ='nat', hook='postrouting', priority=100)

    @property
    def nft(self):
        return self.framework == self.NFTABLES

    @property
    def iptables(self):
        return self.framework == self.IPTABLES

    # here starts "constants" and methods to validate some keywords

    IPTABLES = False
    NFTABLES = True

    # so to use with case=self.nft in many (all?) cases

    @staticmethod
    def valid_keyword(keyword, keywords):
        return keyword in keywords

    @staticmethod
    def validate_keyword(keyword, keywords, case, default=None):
        if case == FwTables.IPTABLES:
            keyword = keyword.upper() if keyword is not None else None
            default = default.upper() if default is not None else None
        else:
            keyword = keyword.lower() if keyword is not None else None
            default = default.lower() if default is not None else None
        return keyword if FwTables.valid_keyword(keyword, keywords[case]) \
            else (default if FwTables.valid_keyword(default, keywords[case]) else None)

    TARGETS = {
        NFTABLES: ['accept', 'drop', 'jump', 'reject', 'dnat', 'snat', 'masquerade', 'log'],
        IPTABLES: ['ACCEPT', 'DROP', 'JUMP', 'REJECT', 'DNAT', 'SNAT', 'MASQUERADE', 'LOG'],
    }

    @staticmethod
    def validate_target(target, case=NFTABLES):
        '''
        Default if not defined goes to None
        '''
        return FwTables.validate_keyword(target, FwTables.TARGETS, case, default=None)

    @staticmethod
    def validate_targets(targets, case=NFTABLES):
        '''
        Default if not defined goes to None
        '''
        return [t for t in
                [FwTables.validate_target(target, case=case) for target in targets]
                if t is not None]

    POLICIES = {
        NFTABLES: TARGETS[NFTABLES][0:2],
        IPTABLES: TARGETS[IPTABLES][0:2],
    }

    @staticmethod
    def validate_policy(policy, default=None, case=NFTABLES):
        '''
        Default if not defined goes to None
        '''
        return FwTables.validate_keyword(policy, FwTables.POLICIES, case, default=default)

    TABLE_FAMILIES = {  # used only in nftables
        NFTABLES: ['ip', 'ip6', 'arp', 'bridge', 'inet', 'netdev'],
        IPTABLES: ['ip', 'ip6', 'arp', 'bridge', 'inet', 'netdev'],
    }

    @staticmethod
    def validate_table_family(family, default=None, case=NFTABLES):
        '''
        Default if not defined goes to 'ip' family type
        '''
        return FwTables.validate_keyword(family, FwTables.TABLE_FAMILIES, case,
                                         default='ip' if default is None else default)

    CHAIN_TYPES = {  # used only in nftables
        NFTABLES: ['filter', 'route', 'nat'],
        IPTABLES: ['filter', 'route', 'nat'],
    }

    # route chaintype in nftables equals to the iptables mangle table

    @staticmethod
    def validate_chain_type(typ, default=None, case=NFTABLES):
        '''
        Default if not defined goes to None (for non-base chains)
        '''
        return FwTables.validate_keyword(typ, FwTables.CHAIN_TYPES, case, default=default)

    CHAIN_HOOKS = {  # used only in nftables
        NFTABLES: ['prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress'],
        IPTABLES: ['prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress'],
    }

    @staticmethod
    def validate_chain_hook(typ, default=None, case=NFTABLES):
        '''
        Default if not defined goes to None (for non-base chains)
        '''
        return FwTables.validate_keyword(typ, FwTables.CHAIN_HOOKS, case, default=default)

    META_STATE = {
        NFTABLES: ['new', 'established', 'related', 'invalid', 'untracked'],
        IPTABLES: ['NEW', 'ESTABLISHED', 'RELATED', 'INVALID', 'UNTRACKED'],
    }

    @staticmethod
    def validate_meta_states(typ, case=IPTABLES):
        # type: (list, int) -> str
        '''
        Returns comma-separated list of valid states.
        Returns empty string if no valid state is found.
        Valid state is a list of states string.
        '''
        return ','.join([state for state in [
            FwTables.validate_keyword(s, FwTables.META_STATE, case) for s in typ
            ] if state is not None])

    # here management methods

    def update(self, tables):
        for family in tables:
            othe_f = tables[family]
            if family not in self._tables:
                self._tables[family] = copy.deepcopy(othe_f)
                continue
            self_f = self._tables[family]
            for table in othe_f:
                if table not in self_f:
                    # if table present only in second set, deepcopy all the table
                    self_f[table] = copy.deepcopy(othe_f[table])
                else:
                    # else check for chains
                    for chain in othe_f[table]:
                        # should check also for chain parameters?
                        if chain not in self_f[table]:
                            # if chain present only in second set, deepcopy all the chain
                            self_f[table][chain] = copy.deepcopy(othe_f[table][chain])
                        else:
                            # else extend the rules list with one in the second set
                            self_f[table][chain]['rules'].extend(othe_f[table][chain]['rules'])

    def clean_rules(self):
        for family in self._tables:
            f = self._tables[family]
            for table in f:
                t = f[table]
                for chain in t:
                    t[chain]['rules'] = []

    # here starts methods to add tables/chains

    def add_table(self, table, family=None):
        '''
        adds a table of name 'table' in-program.
        if necessary for translation a line for creating this should be made (like for nftables),
        but for example in iptables default tables (filter,mangle...) don't need to be defined explicitly
        '''
        family = FwTables.validate_table_family(family, default='ip', case=FwTables.NFTABLES)
        self._tables.setdefault(family, {})
        if table in self._tables[family]:
            raise KeyError('Table {0} already exists for family {1}'.format(table, family))
        self._tables[family][table] = {}

    def add_chain(self, table, chain, family=None, typ=None, hook=None, priority=None, policy=None, device=None):
        '''
        adds a chain of name 'chain' in table of name 'table' in-program.
        if necessary for translation a line for creating this should be made (like for nftables),
        but in iptables default chains (filter.INPUT, mangle.PREROUTING...) don't need to be defined explicitly
        '''
        family = FwTables.validate_table_family(family, default='ip')
        chains = self._tables[family][table]
        if chain in chains:
            raise KeyError('Chain {1} in table {0} for family {2} already exists'.format(table, chain, family))
        chains[chain] = {}
        chains[chain]['rules'] = []
        chains[chain]['type'] = FwTables.validate_chain_type(typ)
        chains[chain]['hook'] = FwTables.validate_chain_hook(hook)
        if chains[chain]['hook'] == 'ingress' and device:
            chains[chain]['device'] = device
        elif chains[chain]['hook'] == 'ingress':
            raise MignisException(self.mignis,
                                  "A chain with ingress hook must define a device (~interface).\n{}"
                                  .format(str(chains[chain])))
        chains[chain]['priority'] = priority if isinstance(priority, (int, long)) else 0
        chains[chain]['policy'] = FwTables.validate_policy(policy)

    def add_rule(self, table, chain, family='ip', **usr_params):
        params = {
            # The rule as written in the configuration file (expanded)
            'abstract': usr_params.get('abstract', None),
            # A user comment for that rule
            'comment': usr_params.get('comment', None),
            # Custom filters for the rule
            'filters': usr_params.get('filters', ''),
            # source/destination
            'protocols': set(Rule.get_protocols(usr_params)),
            # packet state (new/invalid...)
            'states': set(usr_params.get('states', '')),
            # targets
            'targets': usr_params.get('targets', []),
            'snat': usr_params.get('snat', ''),
            'dnat': usr_params.get('dnat', ''),
            'jump': usr_params.get('jump', ''),
            # count?
            'counter': bool(usr_params.get('counter', True)),
            # log prefix
            'log_prefix': usr_params.get('log_prefix', ''),
            'source': {
                'ips': set(),
                'intf': set(),
                'ports': set(),
            },
            'destination': {
                'ips': set(),
                'intf': set(),
                'ports': set(),
            },
        }
        for direction in ['source', 'destination']:
            original = usr_params.get(direction, {})
            if 'ip' in iterkeys(original) and original['ip']:
                params[direction]['ips'].add(original['ip'])
            if 'ips' in iterkeys(original) and original['ips']:
                params[direction]['ips'] = params[direction]['ips'].union(original['ips'])
            if 'intf' in iterkeys(original) and original['intf']:
                params[direction]['intf'].add(original['intf'])
            if 'port' in iterkeys(original) and original['port']:
                params[direction]['ports'].add(tuple(original['port']))
        if 'target' in usr_params:
            params['targets'].append(usr_params['target'])
        params['targets'] = FwTables.validate_targets(params['targets'])
        family = FwTables.validate_table_family(family, default='ip')
        # if not params['targets'] and not params['dnat'] and not params['snat'] and not params['jump']:
        #     raise ValueError("No targets found!")
        self._tables[family][table][chain]['rules'].append(params)

    @staticmethod
    def _rule_has_ports(params):
        return bool(params.get('source').get('ports') or params.get('destination').get('ports')
                    or ':' in params.get('snat') or ':' in params.get('dnat'))


    def _merge_if_mergeable_no_comments(self, f, s, is_near=False):
        # type: (dict, dict) -> dict, bool

        # if second rule is redundant (simply contained or equal to first one)
        #   it can be deleted (merge without change)
        # if second rule has only one mergeable difference
        #   it can be merged only if is_near is set
        #   so we're sure we can anticipate second rule without affecting real order of evaluation
        # in particular can be merged in case of
        # * ONLY one between protocols, source/destination elements

        if f is None:
            return f, False
        if s is None:
            return f, True

        # print("***")
        # print(f['source'])
        # print(s['source'])
        # print(f['destination'])
        # print(s['destination'])

        if f['filters'] != s['filters']:  # cannot check custom filters for equality
            # print("Filters:\n{}\n{}".format(f['filters'], s['filters']))
            return f, False

        if f['states'] != s['states']:  # different packet state => not mergeable
            # print("States:\n{}\n{}".format(f['states'], s['states']))
            return f, False

        if f['targets'] != s['targets']:  # different targets => not mergeable
            # print("targets:\n{}\n{}".format(f['targets'], s['targets']))
            return f, False
        if f['snat'] != s['snat']:  # different source nat => not mergeable #TODO
            # print("snat:\n{}\n{}".format(f['snat'], s['snat']))
            return f, False
        if f['dnat'] != s['dnat']:  # different destination nat => not mergeable #TODO
            # print("dnat:\n{}\n{}".format(f['dnat'], s['dnat']))
            return f, False
        if f['jump'] != s['jump']:  # different jump chain => not mergeable
            # print("Jump:\n{}\n{}".format(f['jump'], s['jump']))
            # (for current mignis behavior, because in nft they could be merged, if this is the only difference)
            return f, False

        if f['log_prefix'] != s['log_prefix']:  # difference in log_prefix => not mergeable
            return f, False

        if f['counter'] != s['counter']:  # difference in counting => not mergeable
            return f, False

        def f_contains_s(csd, what, checker):
            # type: (str, str, callable) -> bool
            # check if f contanis s with regards to checker (could also say "equal")
            return all(map(lambda ip: any(map(lambda x: checker(x, ip), s[csd][what])), f[csd][what]))

        # if one between source/dest ip/port/intf and protocols is different, it can be merged
        # if more are different, but all seconds are included (or equal) in first, second is redundant
        # when merging protocols, no importance is given if ports are defined, because this is managed in translating
        # is preferrable to merge source/destination rather then protocol:
        #  protocols with ports defined gets splitted also with nftables
        def conf(csd, what, checker):
            # type: (str, str, callable) -> bool
            # if both aren't specified, they're the same
            # else they both need to be specified and to be equals for checker
            # for ips there is a case where one is 0.0.0.0/0 and the other not specified... they should be the same :/
            return (not f[csd][what] and not s[csd][what]) \
                   or (bool(s[csd][what]) and bool(f[csd][what]) and f_contains_s(csd, what, checker))

        conf_list = [
            conf('source', 'ips', Rule.ip_equals),
            conf('source', 'ports', Rule.port_equals),
            conf('destination', 'ips', Rule.ip_equals),
            conf('destination', 'ports', Rule.port_equals),
            f['source']['intf'] == s['source']['intf'],
            f['destination']['intf'] == s['destination']['intf'],
            f['protocols'] == s['protocols'],
        ]
        # print("could be")
        # print(conf_list, is_near, sum(conf_list))
        if all(conf_list):
            # second rule is redundant (equals to first rule)
            return f, True
        if sum(conf_list) == len(conf_list) - 1:  # True == 1, so this is if only one in conf_list is not True
            merged = False

            def merge(csd, what, checker):
                # type: (str, str, callable) -> bool
                if bool(f[csd][what]) and bool(s[csd][what]):
                    # if both have values, delete included and add others
                    first = set(f[csd][what])
                    second = set(s[csd][what])
                    for x in s[csd][what]:
                        inside = False
                        firstinside_elem = []
                        for ip in first:
                            inside = inside or checker(x, ip)
                            if is_near and not inside and checker(ip, x):
                                firstinside_elem.append(ip)
                        if inside:
                            # inside gets True if x is included in an element of first
                            # so in that case simply remove x from second
                            second.remove(x)
                        elif firstinside_elem:
                            # elements from first gets added to firstinside_elem if inside is False, rules are near
                            #  and if that element from first is inside x
                            # so if it contains elements, means that an element from first gets removed in favor of x
                            first.add(x)
                            second.remove(x)
                            for elem in firstinside_elem:
                                first.remove(elem)
                        elif is_near:
                            # if no inclusion is available, the element from second can be moved iff rules are near
                            first.add(x)
                            second.remove(x)
                    # if second got totally merged, because inside xor near
                    if not second:
                        f[csd][what] = set(first)
                        return True
                    return False
                elif not f[csd][what] or (not s[csd][what] and is_near):
                    # if one doesn't have values, the merging is obtained not filtering by it
                    f[csd][what] = set()
                    return True

            def mergesets(csd, what=None):
                if what:
                    if not f[csd][what] or (not s[csd][what] and is_near):
                        f[csd][what] = set()
                        return True
                    elif f[csd][what] and s[csd][what] and is_near:
                        f[csd][what] = f[csd][what].union(s[csd][what])
                        return True
                else:
                    if not f[csd] or (not s[csd] and is_near):
                        f[csd] = set()
                        return True
                    elif f[csd] and s[csd] and is_near:
                        f[csd] = f[csd].union(s[csd])
                        return True
                return False

            if not conf_list[0]:
                if self.iptables:  # merging ips in iptables translation is unuseful (they get splitted)
                    return f, False
                merged = merge('source', 'ips', Rule.ip_isinside)
            elif not conf_list[1]:
                merged = merge('source', 'ports', Rule.port_isinside)
            elif not conf_list[2]:
                if self.iptables:  # merging ips in iptables translation is unuseful (they get splitted)
                    return f, False
                merged = merge('destination', 'ips', Rule.ip_isinside)
            elif not conf_list[3]:
                merged = merge('destination', 'ports', Rule.port_isinside)
            elif not conf_list[4]:  # source interface
                if self.iptables:  # merging interfaces in iptables translation is unuseful (they get splitted)
                    return f, False
                merged = mergesets('source', 'intf')
            elif not conf_list[5] and is_near:  # destination interface
                if self.iptables:  # merging interfaces in iptables translation is unuseful (they get splitted)
                    return f, False
                merged = mergesets('destination', 'intf')
            elif not conf_list[6] and is_near:  # protocols
                if self.iptables:  # merging protocols in iptables translation is unuseful (they get splitted)
                    return f, False
                if self.nft and (self._rule_has_ports(f) or self._rule_has_ports(s)):
                    # not merging if rule has ports defined, because they'll get splitted anyway
                    return f, False
                merged = mergesets('protocols')
            if merged:
                # print("***merged***")
                # print(f['source'])
                # print(f['destination'])
                return f, True

        def inconf(csd, what, checker):
            # type: (str, str, callable) -> bool
            # if first hasn't ips/ports specified second is included, because if:
            #   second neither, it is the same
            #   second yes, not specified = every ip/port
            # then if first is specified and second not, that's a false (contrary of before)
            # if both specified... needs checker
            return not f[csd][what] or (bool(s[csd][what]) and f_contains_s(csd, what, checker))

        def setconf(csd, what=None):
            # type: (str, str) -> bool
            # if first set hasn't value, it covers all interfaces/protocols of eventual second
            # else second needs to be specified and first to be superset of it
            # N.B. keyword 'all' is considered as protocol itself
            if what:
                return not f[csd][what] or (bool(s[csd][what]) and f[csd][what].issuperset(s[csd][what]))
            return not f[csd] or (bool(s[csd]) and f[csd].issuperset(s[csd]))

        conf_list = [  # if first and second are equal, second is inside first
            conf_list[0] or inconf('source', 'ips', Rule.ip_isinside),
            conf_list[1] or inconf('source', 'ports', Rule.port_isinside),
            conf_list[2] or inconf('destination', 'ips', Rule.ip_isinside),
            conf_list[3] or inconf('destination', 'ports', Rule.port_isinside),
            conf_list[4] or setconf('source', 'intf'),
            conf_list[5] or setconf('destination', 'intf'),
            conf_list[6] or setconf('protocols'),
        ]
        if all(conf_list):
            # second rule is redundant (some contained in first rule/some equals)
            return f, True
        return f, False

    def _merge_if_mergeable(self, r, s, is_near=False):
        r, merged = self._merge_if_mergeable_no_comments(r, s, is_near=is_near)
        if merged:
            if s['abstract']:
                if r['abstract']:
                    r['abstract'] = r['abstract'] + ' & ' + s['abstract']
                else:
                    r['abstract'] = s['abstract']
            if s['comment']:
                if r['comment']:
                    r['comment'] = r['comment'] + ' || ' + s['comment']
                else:
                    r['comment'] = s['comment']
        return r, merged

    def _merge_all_mergeable(self, family=None, table=None, chain=None):
        if family is None:
            for family in self._tables:
                self._merge_all_mergeable(family=family)
            return
        if table is None:
            for table in self._tables[family]:
                self._merge_all_mergeable(family=family, table=table)
            return
        if chain is None:
            for chain in self._tables[family][table]:
                self._merge_all_mergeable(family=family, table=table, chain=chain)
            return
        rules = self._tables[family][table][chain]['rules']
        onemerged = True
        # print("****merging****")
        # print(len(rules))
        while onemerged:
            onemerged = False
            newrules = []
            while rules:
                rule = rules[0]
                near = 1
                for i in range(1, len(rules)):
                    rule, merged = self._merge_if_mergeable(rule, rules[i], i == near)  # type: dict, bool
                    if merged:
                        onemerged = True
                        near = near + 1
                        rules[i] = None
                rules = filter(None, rules[1:])
                newrules.append(rule)
            rules = newrules
            # if onemerged:
            #     print("****remerging****")
            #     print(len(rules))
        self._tables[family][table][chain]['rules'] = rules

    optimize = _merge_all_mergeable

    def get_rules(self, framework, family=None):
        self.framework = framework
        if self.mignis.optimize:
            self.optimize()
        return self._get_rules_list(family=family)

    def get_iptables_rules(self, family=None):
        return self.get_rules(FwTables.IPTABLES, family=family)

    def get_nftables_rules(self, family=None):
        return self.get_rules(FwTables.NFTABLES, family=family)

    def get_config_rules(self, framework=False, family=None):
        self.framework = framework
        return self._get_config_rules(family=family)

    def _get_policy(self, family, table, chain):
        policy = self.validate_policy(self._tables[family][table][chain]['policy'], case=self.framework)
        if not policy:
            raise MignisException(self.mignis, 'Incorrect policy "{p}" defined for chain {t}/{c} ({f})'.format(f=family, t=table, c=chain, p=self._tables[family][table][chain]['policy']))
        if self.iptables:
            if table == 'filter':
                return '-P {1} {2}'.format(table, chain.upper(), policy)
            else:
                return '-t {0} -P {1} {2}'.format(table, chain.upper(), policy)
        elif self.nft:
            return 'add rule {f} {t} {c} {p} comment "{p} policy"'.format(f=family, t=table, c=chain, p=policy)

    def _get_config_rules(self, family=None):
        rules_list = []
        if family is None:
            for family in self._tables:
                rules_list.extend(self._get_config_rules(family))
            return rules_list
        family = FwTables.validate_table_family(family, default='ip', case=FwTables.NFTABLES)
        for table in self._tables[family]:
            if self.nft:
                rules_list.append('add table {family} {name}'.format(family=family, name=table))
            for chain in self._tables[family][table]:
                c = self._tables[family][table][chain]
                if self.nft:
                    config = ''
                    if c['type'] and c['hook']:
                        config = ' {'
                        config += ' type {0}'.format(c['type'])
                        config += ' hook {0}'.format(c['hook'])
                        if c['hook'] == 'ingress':  # device must be set, add_chain should raise exception in this case
                            config += ' device {0}'.format(c['device'])
                        if c['priority'] or c['priority'] == 0:
                            config += ' priority {0}'.format(c['priority'])
                        if config != '':
                            config += ' ;'
                        # WARNING: in nftables policy only available from version 0.5
                        if c['policy']:  # default nftables policy is accept
                            config += ' policy {0} ;'.format(FwTables.validate_policy(c['policy'], case=self.NFTABLES))
                        # policy is always set in chain config, but must be set here only if base chain
                        # (so with type-hook setted)
                        config += ' }'
                    rules_list.append('add chain {family} {table} {chain}{config}'
                                      .format(family=family,
                                              table=table,
                                              chain=chain,
                                              config=config,
                                              )
                                      )
                    # set policy if non-base chain
                    if not config and c['policy']:
                        rules_list.append(self._get_policy(family, table, chain))
                elif self.iptables:
                    if table == 'raw':
                        add_chain = chain not in ('prerouting', 'output')
                    elif table == 'mangle':
                        add_chain = chain not in ('prerouting', 'input', 'output', 'forward', 'postrouting')
                    elif table == 'nat':
                        add_chain = chain not in ('prerouting', 'output', 'forward', 'postrouting')
                    elif table == 'filter':
                        add_chain = chain not in ('input', 'output', 'forward')
                    else:
                        add_chain = True
                        # TODO: raise MignisException? in iptables cannot create tables
                    if add_chain:
                        rules_list.append('{0}-N {1}'.format('' if table == 'filter' else '-t {} '.format(table),
                                                             chain.upper())
                                          )
                    if c['policy']:
                        rules_list.append(self._get_policy(family, table, chain))
        return rules_list

    def _get_rules_list(self, family=None):
        rules_list = []
        if family is None:
            for family in self._tables:
                rules_list.extend(self._get_rules_list(family))
            return rules_list
        family = FwTables.validate_table_family(family, default='ip', case=FwTables.NFTABLES)
        for table in self._tables[family]:
            for chain in self._tables[family][table]:
                for rule in self._tables[family][table][chain]['rules']:
                    params = copy.deepcopy(rule)
                    rules_list.extend(self._get_rule(family, table, chain, **params))
        return rules_list

    _iptables_protocols_with_ports = 'tcp,udp,sctp,dccp'.split(',')
    _nft_protocols_with_ports = 'tcp,udp,udplite,sctp,dccp'.split(',')
    # list of protocols with ports from https://wiki.gentoo.org/wiki/Nftables#Matches

    @property
    def _protocols_with_ports(self):
        if self.nft:
            return FwTables._nft_protocols_with_ports
        if self.iptables:
            return FwTables._iptables_protocols_with_ports
        return []

    @staticmethod
    def _make_nft_set(iterable, final=False):
        str_itr = ' , '.join(iterable)
        if str_itr.count(',') > 0:
            if final:
                return '{ ' + str_itr + ' }'
            return '{{ ' + str_itr + ' }}'
        return str_itr

    def _format_ipport_duple(self, duple):
        if self.nft or self.iptables:
            return str(duple[0]) + (':' + '-'.join(map(str, duple[1])) if duple[1] else '')
        return ''

    def _get_rule(self, family, table, chain, **params):
        '''
        this method translate an FwTable rule in a real iptables/nftables rule
        final rules returned are simple strings (list of)
        '''
        rule = ''
        pieces = defaultdict(list)

        # start source & destination + protocol
        # first sanitize protocol 'all' for framework defined.
        protocols_with_ports = self._protocols_with_ports
        protocols = params['protocols']
        if 'all' in protocols:
            self.mignis.warning("Ports have been specified without a protocol."
                                " Using all protocols that support ports ({0}). In rule: {1}"
                                .format(', '.join(protocols_with_ports),
                                        params['abstract']))
            protocols.remove('all')
            protocols = protocols.union(protocols_with_ports)
        npports = list(protocols)

        if protocols:
            if self.nft:
                rule += ' {protocol} '
            elif self.iptables:
                rule += ' {protocol} '
        port_lists = defaultdict(list)
        for direction, sd, srcdst, intfio in [('source', 's', 'src', 'i'), ('destination', 'd', 'dst', 'o')]:
            intfip = params[direction]
            if self.nft:
                # start NFT
                if intfip['intf']:
                    rule += ' meta {0}if{2} {1} '.format(intfio, self._make_nft_set(intfip['intf']), '' if self.mignis.optimize >= 2 else 'name')
                    # oif/iif are faster than oifname and iifname, but can lead to some issues with dynamic interfaces
                    # see https://home.regit.org/netfilter-en/nftables-quick-howto/ => Filter on interface
                if len(intfip['ips']) > 0:
                    rule += ' {2} {0}addr {1} '.format(sd, self._make_nft_set(map(str, intfip['ips'])), family)
                # end NFT
            if self.iptables:
                # start IPTABLES
                if intfip['intf']:
                    rule += ' -{0} {1} '.format(intfio, '{' + intfio + 'intf}')
                    pieces[intfio + 'intf'] = intfip['intf']
                if intfip['ips']:
                    rule += ' {' + direction + 'ip} '
                    pieces[direction + 'ip'] = []
                    for ip in intfip['ips']:
                        if isinstance(ip, IPv4Range):
                            pieces[direction + 'ip'].append(' -m iprange --{0}-range {1} '.format(srcdst, str(ip)))
                        else:
                            pieces[direction + 'ip'].append(' -{0} {1}'.format(sd, str(ip)))
                # end IPTABLES
            if intfip['ports']:
                intfip['ports'] = [':'.join(map(str, port)) for port in intfip['ports']]
                # print('ports: {} - protocols: {}'.format(str(intfip['ports']), str(protocols)))
                for proto in protocols.intersection(protocols_with_ports):
                    # print('ports: '+proto+' '+str(proto in protocols_with_ports)+' '+str(protocols_with_ports))
                    ports = ''
                    pt = ''
                    if self.iptables:
                        if len(intfip['ports']) > 1:
                            ports = ','.join(intfip['ports'])
                            pt = '-m multiport --{0}ports {1}'
                        else:
                            ports = intfip['ports'][0]
                            pt = '--{0}port {1}'
                    if self.nft:
                        ports = self._make_nft_set(intfip['ports'], final=True)
                        pt = '{0}port {1}'
                    port_lists[proto].append(pt.format(sd, ports))
                    try:
                        npports.remove(proto)
                    except ValueError:
                        pass
        for proto, port_list in iteritems(port_lists):
            if self.iptables:
                pieces['protocol'].append('-p {0} {1}'.format(proto, ' '.join(port_list)))
            elif self.nft:
                pieces['protocol'].append('{0} {1}'.format(proto, (' ' + proto + ' ').join(port_list)))
        if npports:
            # print("npports: "+str(npports))
            if self.nft:
                pieces['protocol'].append('{1} protocol {0}'.format(self._make_nft_set(npports, final=True), family))
            elif self.iptables:
                for proto in npports:
                    pieces['protocol'].append('-p ' + proto)
        # end source & destination + protocol

        # filters
        if params['filters']:
            filters = ''
            ffs = params['filters'].split('|')
            for ff in ffs:
                if len(ff) > 3 and ff[0:3] == 'nft':
                    if self.nft:
                        filters = ff[3:]
                elif self.iptables:
                    filters = ff
            rule += ' {} '.format(filters)

        # state
        if params['states']:
            states = FwTables.validate_meta_states(params['states'], case=self.framework)
            if self.nft:
                rule += ' ct state ' + states
            elif self.iptables:
                rule += ' -m state --state ' + states

        # targets
        tlist = params['targets']  # already validated and lowered in add_rule
        targets = []

        if 'log' in tlist:
            l = 'log'
            p = ''
            if 'log_prefix' in params and params['log_prefix']:
                p = 'prefix "{}"'.format(params['log_prefix'].replace('"', '\\"'))
            if self.iptables:
                l = l.upper()
                p = '--log-' + p if p else ''
            targets.append(l + ' ' + p)

        if params['jump']:  # TODO introduce GOTO?
            if params['jump'] not in self._tables[family][table]:
                raise MignisException(self.mignis,
                                      "Defined a jump target to non-existent chain.\n{0}".format(params['abstract']))
            if self.nft:
                targets.append('jump ' + params['jump'])
            elif self.iptables:
                targets.append(params['jump'])

        # TODO: add flags for nft?
        # => http://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#NAT_flags
        nat = ''
        if params['snat']:
            nat = 'SNAT'
            if self.nft:
                targets.append('snat {}'.format(self._format_ipport_duple(params['snat'])))
            else:
                targets.append('SNAT --to-source {}'.format(self._format_ipport_duple(params['snat'])))
        elif 'masquerade' in tlist:
            nat = 'MASQUERADE'
            if self.nft:
                targets.append('masquerade')
            else:
                targets.append('MASQUERADE')
        if params['dnat']:
            nat = 'DNAT'
            if self.nft:
                targets.append('dnat {}'.format(self._format_ipport_duple(params['dnat'])))
            else:
                targets.append('DNAT --to-destination {}'.format(self._format_ipport_duple(params['dnat'])))
        if nat:
            # raise exceptions if nat rule added in non-nat chain. if chain not hooked it's ok (maybe a goto/jump)
            if self.nft \
                    and self._tables[family][table][chain]['hook'] \
                    and self._tables[family][table][chain]['type'] != 'nat':
                raise MignisException(self.mignis,
                                      "NFTABLES: Defined a {} in incorrect chain type ({} instead of nat)"
                                      .format(nat, self._tables[family][table][chain]['type']))
            elif self.iptables and table in ['filter', 'mangle', 'raw']:
                raise MignisException(self.mignis,
                                      "IPTABLES: Defined a {} in incorrect table ({} instead of nat)"
                                      .format(nat, table))

        if 'accept' in tlist:
            targets.append(FwTables.validate_target('accept', case=self.framework))
        elif 'drop' in tlist:
            targets.append(FwTables.validate_target('drop', case=self.framework))
        elif 'reject' in tlist:
            targets.append(FwTables.validate_target('reject', case=self.framework))

        if len(targets) == 0:
            raise MignisException(self.mignis, "***FATAL***\nRule without targets is defined!\n"
                                               "If optimization was enabled, please try again without optimization"
                                               " and then report at github!\n{}".format(str(params)))

        if params['counter']:  # or self.counter:  # TODO: add an option to always count
            if self.nft:
                rule = rule + ' counter'
        # in iptables cannot suppress counters

        # comment to the rule
        comment = ''
        if params['abstract'] or params['comment']:
            escaped = ''
            if params['abstract']:
                escaped = params['abstract']
            if params['comment']:
                if escaped:
                    escaped = escaped + ' - '
                escaped = escaped + params['comment']
            # Escape the " character
            escaped = escaped.replace('"', '\\"')
            if self.nft:
                comment = ' comment "{0}"'
            else:
                comment = ' -m comment --comment "{0}"'
            comment = comment.format(escaped)

        # iptables: multiply rules if more targets defined
        # nftables: more targets in same rule
        if self.nft:
            rule += ' ' + ' '.join(targets) + comment
            rule = 'add rule {f} {t} {c} {r}'.format(f=family, t=table, c=chain, r=rule)
        else:
            rule = '-A {chain} ' + rule + ' -j {target} ' + comment
            pieces['target'] = targets
            pieces['chain'] = chain.upper()
            if table != 'filter':
                rule = '-t {table} ' + rule
                pieces['table'] = table
        rules = FwTables._format_multiply_rule(rule, pieces)
        rules = [re.sub('\s+', ' ', r) for r in rules]  # remove extra spaces
        if self.debug >= 1:
            if self.nft:
                pre = 'nft '
            else:
                pre = 'iptables '
            for r in rules:
                print(pre + r)
        return rules

    @staticmethod
    def _format_multiply_rule(rule, pieces):
        # type: (str, dict) -> list
        rules = []
        for key in iterkeys(pieces):
            values = pieces[key]
            if isinstance(values, (list, set)):
                if len(values) > 1:
                    for value in values:
                        pieces[key] = value
                        rules.extend(FwTables._format_multiply_rule(rule, pieces))
                    return rules
                elif len(values) == 1:
                    pieces[key] = values.pop()  # list returns last, set returns one casual element. But there's one ;)
                else:
                    pieces[key] = ''
        rules.append(rule.format(**pieces))
        return rules


class MignisException(Exception):
    def __init__(self, mignis, message):
        Exception.__init__(self, message)
        # mignis.reset_iptables(False)


class MignisConfigException(Exception):
    pass


class Mignis:
    def __init__(self, config_file, debug, force, dryrun, write_rules_filename, execute_rules, optimize, nftables):
        self.config_file = config_file
        self.config_dir = os.path.dirname(self.config_file)
        self.debug = debug
        self.force = force
        self.dryrun = dryrun
        self.write_rules_filename = write_rules_filename
        self.execute_rules = execute_rules
        self.optimize = optimize
        self.nftables = nftables
        '''
        intf contains the alias/interface/subnet mapping for each interface.
        An example of how its structure looks like:
        {
            'lan': ('eth0', IPv4Network('10.0.0.0/24')),
            'ext': ('eth1', IPv4Network('0.0.0.0/0'))
        }
        '''
        self.intf = {}
        # Rules to be executed, as strings, in the correct order
        self.rules_strings = []
        # Rules to be executed, as FwTables object, divided by tables and chains
        self.rules = FwTables(self)
        self.options = {'default_rules': 'yes', 'logging': 'yes'}
        self.aliases = {}
        self.alias_regexp = {}
        self.inverse_alias_regexp = {}
        self.rule_regexp = None
        self.fw_rulesdict = {}
        self.policies_rulesdict = {}
        self.custom = {}
        self.custom_nft = {}
        self.read_config()

    @staticmethod
    def _make_temp_file(suffix=None):
        return tempfile.mkstemp(suffix=suffix or '.mignis', prefix='mignis_')

    @staticmethod
    def _ask_user(question, answers=None, timeout=None):
        # type: (str, list, int) -> str
        # for async main-thread-stoppable question, use multiprocessing (thread aren't easily killable easily)
        answer = ''
        print('')
        answers = map(str.lower, answers or ['y', 'n'])
        question = question + ' [' + '|'.join(answers) + ']: '
        while answer not in answers:
            answer = stdin(question).lower()
        return answer

    def wr(self, s):
        '''Print a string to stdout
        '''
        if self.debug >= 1:
            print(s)

    def execute(self, cmd):
        '''Execute the command cmd only if we are not in dryrun mode
        '''
        # TODO: use subprocess.check_call with try/except in place of system
        # print('\n[*] ' + cmd)
        if self.debug >= 2:
            print('COMMAND: ' + cmd)
        # print('\n[*] Not executing because testing.')
        # return
        ret = os.system(cmd)
        if ret:
            raise MignisException(self, 'Command execution error (code: {0}).'.format(ret))

    def test_exec_rules(self):
        print('\n[*] Applying rules')
        # Create temp file for writing the rules
        temp_fd, temp_file = self._make_temp_file('.ipt')
        self.write_rules(None, fd=temp_fd)

        # Execute the rules.
        # First in dryrun mode, and if no exception is raised they are executed for real.
        self.exec_rules(temp_file, force_dryrun=True)  # this lets check syntax of generated by firewall (iptables/nft)
        self.exec_rules(temp_file)  # this should really apply rules.

        # Delete the temp file
        os.unlink(temp_file)

    def exec_rules(self, temp_file, force_dryrun=False):
        options = ' '
        restore = ''
        tpr = None
        dryrun = self.dryrun or force_dryrun
        # TODO: if not dryrun should always make backup of current rules, at least
        # maybe also restore backup if user don't answer a question (should be suppressible to use in wider scripts)
        if self.nftables:
            command = 'nft'
            options += '-f '
            if dryrun:
                _, tpr = self._make_temp_file('.nft')
                self.execute('echo "flush ruleset" > ' + tpr)
                self.execute('nft list ruleset >> ' + tpr)
                restore = 'nft -f ' + tpr
        else:
            command = 'iptables-restore'
            if dryrun:
                options += '--test '

        try:
            # Execute the rules
            self.execute(command + options + temp_file)
        except MignisException as e:
            if restore:
                self.execute('sleep 2 && ' + restore)
                os.unlink(tpr)
            raise MignisException(self,
                                  str(e) + '\nThe temporary file which generated the error is stored in "{0}"'.format(
                                      temp_file))
        if restore and (force_dryrun or self._ask_user("Restore?") == 'y'):
            self.execute(restore)
        if tpr:
            os.unlink(tpr)

    def write_rules(self, filename, fd=None):
        if self.dryrun:
            return

        if fd:
            f = os.fdopen(fd, 'w')
        else:
            if not self.force and os.path.exists(filename):
                raise MignisException(self, 'The file already exists, use -f to overwrite.')
            f = open(filename, 'w')

        if self.nftables:
            f.write('flush ruleset\n')
            f.write('\n'.join(self.rules_strings) + '\n')
        else:
            # Split the rules in filter, nat and mangle tables
            separators = '[^a-zA-Z0-9\-_]'
            rules = self.rules_strings[:]
            tables = {'filter': [], 'nat': [], 'mangle': []}
            for table, table_opt in [
                ('nat', '(?:\A|{0})(-t nat)(?:\Z|{0})'.format(separators)),
                ('mangle', '(?:\A|{0})(-t mangle)(?:\Z|{0})'.format(separators))
            ]:
                for rule in self.rules_strings:
                    if re.search(table_opt, rule):
                        # Extract the rule without "-t nat" or "-t mangle" switches
                        rules.remove(rule)
                        rule = re.sub(table_opt, '', rule)
                        tables[table].append(rule)
            tables['filter'] = rules

            # Write the rules by table
            for table_name, rules in iteritems(tables):
                f.write('*' + table_name + '\n')
                f.write('\n'.join(rules))
                f.write('\nCOMMIT\n')

        f.close()

    def apply_rules(self):
        if self.dryrun:
            print('\n[*] Rules not applied (dryrun mode)')
        else:
            if self.write_rules_filename:
                self.write_rules(self.write_rules_filename)
                print('\n[*] Rules written.')
            else:
                if self.force:
                    self.test_exec_rules()
                    print('\n[*] Rules applied.')
                else:
                    execute = self._ask_user('Apply the rules?')
                    if execute == 'y':
                        self.test_exec_rules()
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

    def add_rule_string(self, r, pos=-1):
        if self.debug >= 1:
            if self.nftables:
                print('nft ' + r)
            else:
                print('iptables ' + r)
        if pos > -1:
            self.rules_strings.insert(pos, r)
        else:
            self.rules_strings.append(r)

    def all_rules(self):
        '''Builds all rules
        '''
        print('\n[*] Building rules')
        self.mandatory_rules()
        self.ignore_rules()
        if self.options['default_rules'] == 'yes':
            self.default_rules()
        self.firewall_rules()
        self.policies_rules()
        self.ip_intf_binding_rules()
        for rule in self.rules.get_rules(self.nftables):
            self.add_rule_string(rule)
        self.custom_rules()
        if self.options['logging'] == 'yes':
            self.rules.clean_rules()
            self.log_rules()
            for rule in self.rules.get_rules(self.nftables):
                self.add_rule_string(rule)
        # prepend config rules (tables/chains creation and policies) before all other rules
        # done like this because log rules can add chains
        i = 0
        for rule in self.rules.get_config_rules(self.nftables):
            self.add_rule_string(rule, i)
            i = i + 1

    def mandatory_rules(self):
        '''Rules needed for the model to work.
        At this moment we only require an ESTABLISHED,RELATED
        rule on every chain in filter.
        '''
        self.wr('\n# Mandatory rules')
        rule_params = {'states': ['established', 'related'], 'targets': ['accept']}
        self.rules.add_rule('filter', 'input', **rule_params)
        self.rules.add_rule('filter', 'output', **rule_params)
        self.rules.add_rule('filter', 'forward', **rule_params)

    def policies(self):
        '''Default policies for input/forward/output in filter and prerouting in mangle
        '''
        self.wr('\n# Default policies')
        # self.add_iptables_rule('-P INPUT DROP')
        # self.add_iptables_rule('-P FORWARD DROP')
        # self.add_iptables_rule('-P OUTPUT DROP')
        # self.add_iptables_rule('-t mangle -P PREROUTING DROP')

    def ignore_rules(self):
        '''Ignore rules for each interface, if specified as an option
        '''
        self.wr('\n# Ignore rules')
        for i_alias, (i_intf, i_subnet, i_options) in self.intf.items():
            if 'ignore' in i_options:
                ignore_i = {
                    'target': 'accept',
                    'source': {'intf': i_intf},
                    'comment': 'ignore {0}'.format(i_intf)
                }
                ignore_o = {
                    'target': 'accept',
                    'destination': {'intf': i_intf},
                    'comment': 'ignore {0}'.format(i_intf)
                }
                self.rules.add_rule('filter', 'input', **ignore_i)
                self.rules.add_rule('filter', 'output', **ignore_o)
                self.rules.add_rule('filter', 'forward', **ignore_i)
                self.rules.add_rule('filter', 'forward', **ignore_o)
                self.rules.add_rule('mangle', 'prerouting', **ignore_i)

    def default_rules(self):
        '''Default rules.
        Usually safe, they can be disabled using "default_rules no" in the configuration's options section.
        '''
        self.wr('\n# Default rules')
        # Loopback
        self.wr('# - Loopback')
        self.rules.add_rule('filter', 'input', comment='loopback', target='accept', source={'intf': 'lo'})
        # Drop invalid packets
        self.wr('# - Invalid packets')
        self.rules.add_rule('mangle', 'prerouting', comment='drop invalid', target='drop',
                            states=['invalid', 'untracked'])
        # Allow broadcast traffic
        self.wr('# - Broadcast traffic')
        broadcast = {
            'abstract': 'allow broadcast traffic',
            'target': 'accept',
            'destination': {'ip': '255.255.255.255'},
        }
        self.rules.add_rule('filter', 'input', **broadcast)
        self.rules.add_rule('mangle', 'prerouting', **broadcast)
        # Allow multicast traffic
        self.wr('# - Multicast traffic')
        multicast = {
            'abstract': 'allow multicast traffic',
            'target': 'accept',
            'destination': {'ip': '224.0.0.0/4'},
        }
        self.rules.add_rule('filter', 'input', **multicast)
        self.rules.add_rule('mangle', 'prerouting', **multicast)
        # We don't allow packets to go out from the same interface they came in
        # self.wr('# - Same-interface packets')
        # for ipsub in iterkeys(self.intf):
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
                for family, table, chain, params in rule.get_rules(self.fw_rulesdict):
                    self.rules.add_rule(table, chain, family=family, **params)

        # Check if rules overlap
        for (ruletype_a, rules_a) in iteritems(self.fw_rulesdict):
            if ruletype_a == '!':
                continue
            for rule_a in rules_a:
                for (ruletype_b, rules_b) in iteritems(self.fw_rulesdict):
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
        for ruletype in iterkeys(self.policies_rulesdict):
            for rule in self.policies_rulesdict[ruletype]:
                # Debugging info
                if self.debug >= 2:
                    print('\n# [D]\n' + str(rule))
                if self.debug >= 1:
                    print('\n# ' + rule.params['abstract'])
                # Add the rule to iptables
                for family, table, chain, params in rule.get_rules(self.policies_rulesdict):
                    self.rules.add_rule(table, chain, family=family, **params)

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
        for ipsub in iterkeys(self.intf):
            subnet, ip, options = self.intf[ipsub]
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
                if ipsub != 'local':
                    # We exclude all the source IPs defined for the other interfaces
                    ips = []
                    for other_ipsub in iterkeys(self.intf):
                        # Skip if itself
                        if other_ipsub == ipsub:
                            continue
                        other_subnet, other_ip, other_options = self.intf[other_ipsub]
                        # Skip if the interface has no ip
                        if other_ip is None:
                            continue
                        ips.append(other_ip)
                    if ips:
                        options_drop = {'source': {'intf': subnet, 'ips': ips},
                                        'abstract': 'bind any ip to intf {0}'.format(subnet),
                                        'target': 'drop'}
                        self.rules.add_rule('mangle', 'prerouting', **options_drop)
                # Accept rule for all other IPs
                options = {'source': {'intf': subnet},
                           'abstract': 'bind any ip to intf {0}'.format(subnet),
                           'target': 'accept'}
                self.rules.add_rule('mangle', 'prerouting', **options)
            else:
                options = {'source': {'intf': subnet, 'ip': ip},
                           'abstract': 'bind ip {0} to intf {1}'.format(ip, subnet),
                           'target': 'accept'}
                self.rules.add_rule('mangle', 'prerouting', **options)

    def custom_rules(self):
        '''Custom rules are executed verbatim.
        The only exception are aliases, which will be replaced with their
        corresponding value.
        '''
        self.wr('\n## Custom rules')

        if self.nftables:
            # sets: daddr { 1.2.3.4 , alias , another_alias, 5.6.7.8/24, 2.3.4.5-2.3.4.10 }
            # maps: daddr { 1.2.3.4/24 : drop, 80 : alias , another_alias : drop }
            # find_in_set = '(?: *{[a-zA-Z0-9\-_\./, \:]+?)?'
            # to support sets and maps must have non-fixed-width look-behind in regexp...
            # resolved adding '({|,|:)' with and without space.
            intf_switches = ['(i|o)if ', '(i|o)ifname ', '({|,|:)', '({|,|:) ']
            dest_source_switches = ['(d|s)addr ', '({|,|:)', '({|,|:) ']
            custom = self.custom_nft
        else:
            intf_switches = ['-i ', '-o ', '--in-interface ', '--out-interface ']
            dest_source_switches = ['-d ', '-s ', '--destination ', '--source ']
            custom = self.custom

        # Compile the regular expressions
        regexp_alias = {}
        for alias in iterkeys(self.aliases):
            for switch in dest_source_switches:
                regexp_alias.setdefault(alias, []).append(
                    re.compile('(?<={0}){1}(?={2})'.format(switch, alias, '[^a-zA-Z0-9\-_]')))
        regexp_intf = {}
        for alias in self.intf:
            for switch in intf_switches:
                regexp_intf.setdefault(alias, []).append(
                    re.compile('(?<={0}){1}(?={2})'.format(switch, alias, '[^a-zA-Z0-9\-_]')))

        # For each rule, search and replace aliases recursively
        for rule in custom:
            replace_again = True
            while replace_again:
                replace_again = False
                for alias, val in iteritems(self.aliases):
                    '''
                    the re module, when using look-behind, requires a fixed-width pattern.
                    the regex module allows variable-width patterns and thus the following
                    for loop can be replaced by this line:
                    switch = '(-d|-s|--destination|--source) '
                    rule = re.sub(
                                '(?<={0}){1}(?={2})'.format(switch, alias, '[^a-zA-Z0-9\-_]'),
                                val,
                                rule)
                    when the regex module will replace re, we can change this code.
                    '''
                    for n, switch in enumerate(dest_source_switches):
                        new_rule = regexp_alias[alias][n].sub(val, rule)
                        if new_rule != rule:
                            replace_again = True
                            rule = new_rule
                # Search and replace interface aliases
                for alias in self.intf:
                    subnet = self.intf[alias][0]
                    for n, switch in enumerate(intf_switches):
                        new_rule = regexp_intf[alias][n].sub(subnet, rule)
                        if new_rule != rule:
                            replace_again = True
                            rule = new_rule
            self.add_rule_string(rule)
        self.wr('\n##\n')

    def log_rules(self):
        '''Logging rules. We log the filter (input/output/forward) and mangle (prerouting only) tables
        '''
        self.wr('\n# Log')
        self.rules.add_chain('mangle', 'mangle_drop')
        self.rules.add_chain('filter', 'filter_drop')
        targets = ['log', 'drop']
        log_prefix = '{0}-DROP-{1} '
        for proto in ['icmp', 'udp', 'tcp']:
            self.rules.add_rule('mangle', 'mangle_drop', protocol=proto, targets=targets, log_prefix=log_prefix.format("MANGLE", proto))
            self.rules.add_rule('filter', 'filter_drop', protocol=proto, targets=targets, log_prefix=log_prefix.format("FILTER", proto))
        self.rules.add_rule('mangle', 'mangle_drop', targets=targets, log_prefix=log_prefix.format("MANGLE", "UNK"))
        self.rules.add_rule('mangle', 'prerouting', jump='mangle_drop')
        self.rules.add_rule('filter', 'filter_drop', targets=targets, log_prefix=log_prefix.format("FILTER", "UNK"))
        self.rules.add_rule('filter', 'input', jump='filter_drop')
        self.rules.add_rule('filter', 'output', jump='filter_drop')
        self.rules.add_rule('filter', 'forward', jump='filter_drop')

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
                query_address = Rule.expand_address(self, (q_exp, None))
            except AddressValueError as e:
                raise MignisException(self, 'Bad query "{0}"'.format(query))
            query_alias, query_interface, query_ip = query_address['alias'], query_address['intf'], query_address['ip']

            if query_len == 1:
                print('\n[*] Query:\n  alias: {0}\n  intf:  {1}\n  ip:    {2}'.format(query_alias, query_interface, query_ip))
                print('\n[*] Results')

            # For each rule, check if it involves query and print the collapsed version of the rule
            # along with the single rule.
            # It avoids writing the same collapsed rule multiple times.
            for ruletype in ['/', '//', '<>', '>', '>D', '>M', '>S', '{']:
                for rule in self.fw_rulesdict[ruletype]:
                    abstract_collapsed = rule.params['abstract_collapsed']
                    abstract = rule.params['abstract']
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

        # # Check if rules overlap
        # for (ruletype_a, rules_a) in iteritems(q_rulesdict):
        #    if ruletype_a == '/': continue
        #    for rule_a in rules_a:
        #        for (ruletype_b, rules_b) in iteritems(self.fw_rulesdict):
        #            if ruletype_b == '/': continue
        #            for rule_b in rules_b:
        #                if rule_b is rule_a: continue
        #                # Check if rule_a and rule_b overlap
        #                if rule_b.overlaps(rule_a):
        #                    print(rule_b.params['abstract'])

        self.wr('##')

    def config_get(self, what, config, split_separator='\s+', split_count=0, split=True):
        '''Read a configuration section. 'what' is the configuration section name,
        while 'config' is the whole configuration as a string.
        Returns a list where each element is a line, and every element is a list
        containing the line splitted by 'split_separator'.
        '''
        if what not in config:
            raise MignisConfigException('Missing section "{0}" in the configuration file.'.format(what))

        r = re.search('(.*?)(\n*\Z)', config[what], re.DOTALL)
        if r and r.groups():
            # Get the section contents and split by line
            r = r.groups()[0].strip().split('\n')
            # Remove comments and empty lines
            r = filter(lambda x: x and x[0] != '#', r)
            if split:
                # Split each line by separator
                r = map(lambda x: map(string.strip, re.split(split_separator, x, split_count)), r)
            return r
        else:
            return []

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
            ports = map(int, r[1].split('-'))
            if len(ports) > 2 or \
                    ports[0] < 0 or ports[0] > 65535 or \
                    (len(ports) == 2 and (ports[1] < 0 or ports[1] > 65535 or ports[0] > ports[1])):
                raise MignisConfigException('invalid port range "{0}".'.format(ports))
            r[1] = ports
        return r

    def expand_rule(self, rule):
        # Convert aliases
        # TODO: this is truly ugly. Do a better replacement for aliases
        replace_again = True
        while replace_again:
            replace_again = False
            for alias, val in iteritems(self.aliases):
                new_rule = self.alias_regexp[alias].sub(val, ' ' + rule + ' ')[1:-1]
                if new_rule != rule:
                    replace_again = True
                    rule = new_rule

        # Create a list of lists, splitting on ", *" for each list found.
        # Each list is written using "(item1, item2, ...)".
        rules = map(lambda x: re.split(', *', x), filter(None, re.split('[()]', rule)))

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
                for alias, val in iteritems(self.aliases):
                    abstract_rule = self.inverse_alias_regexp[val].sub(alias, ' ' + abstract_rule + ' ')[1:-1]
                abstract_rule = (abstract_rule + ' ' + params).strip()

                if self.debug >= 3:
                    print("    expanded rule: {0}".format([abstract_rule, params]))

                # rule = re.search('^(.*?) *(\[.*?\])? (/|//|>|<>) (\[.*?\])? *(.*?)$', rule)
                rule = self.rule_regexp.search(rule)
                if not rule:
                    raise MignisConfigException('bad firewall rule "{0}".'.format(rule))
                rule = rule.groups()
                if self.debug >= 3:
                    print("    rule regexped: {0}".format(rule))
                (r_from, r_nat_left, ruletype, r_nat_right, r_to, protocol) = rule

                r_from = self.config_split_ipport(r_from)
                r_to = self.config_split_ipport(r_to)
                if self.debug >= 3:
                    print("    rule regexped: {0}".format((r_from, r_nat_left, ruletype, r_nat_right, r_to, protocol)))

                # Find and replace aliases inside params
                if params:
                    for alias, val in iteritems(self.aliases):
                        params = self.alias_regexp[alias].sub(val, ' ' + params + ' ')[1:-1]

                nat = None
                if ruletype == '>':
                    if r_nat_left and r_nat_right:
                        raise MignisConfigException('bad firewall rule in configuration file.')
                    if r_nat_left:
                        # SNAT
                        if r_nat_left == '[.]':
                            # Masquerade
                            ruletype = '>M'
                        else:
                            # Classic SNAT
                            ruletype = '>S'
                            nat = self.config_split_ipport(r_nat_left[1:-1])
                    elif r_nat_right:
                        # DNAT
                        ruletype = '>D'
                        nat = self.config_split_ipport(r_nat_right[1:-1])
                        # else:
                        # Forward
                        # pass
                elif ruletype not in ['/', '//', '<>']:
                    # Deny, Reject, Bidirectional forward
                    raise MignisConfigException('bad firewall rule in configuration file.')
                try:
                    r = Rule(self, abstract_rule, abstract_rule_collapsed, ruletype, r_from, r_to, protocol, params, nat)
                except RuleException as e:
                    raise MignisConfigException(str(e))

                if inside_sequence:
                    rulesdict['{'].append(r)
                else:
                    rulesdict[ruletype].append(r)

        if self.debug >= 2:
            pprint.pprint(rulesdict, width=200)

        return rulesdict

    def config_include(self, match):
        filename = match.groups()[0]
        if not filename:
            raise MignisConfigException('Invalid include directive "{0}".'.format(match.group()))

        filename = self.config_dir + '/' + filename
        try:
            return open(filename).read().strip()
        except:
            raise MignisConfigException('Unable to read file "{0}" for inclusion.'.format(filename))

    def read_config(self):
        '''Parses the configuration file and populates the rulesdict dictionary
        '''
        try:
            print("[*] Reading the configuration")
            config = open(self.config_file).read()

            # Execute the @include directives (recursively)
            old_config = ''
            while config != old_config:
                old_config = config
                config = re.sub('(?<=\n)@include[ \t]+(.*?)(?=\n)', self.config_include, config)

            # Replace every sequence of tabs and spaces with a single space
            config = re.sub('[ \t]+', ' ', config)

            # Split by section
            config = re.split('(OPTIONS|INTERFACES|ALIASES|FIREWALL|POLICIES|CUSTOM|CUSTOM-NFTABLES)\n', config)[1:]
            config = dict(zip(config[::2], config[1::2]))

            # Read the options
            options = self.config_get('OPTIONS', config)
            # Convert to lowercase and to a dictionary
            options = dict([tuple([y.lower() for y in x]) for x in options])
            self.options.update(**options)

            # Read the interfaces
            intf = self.config_get('INTERFACES', config)
            for x in intf:
                if len(x) < 3 or len(x) > 4:
                    raise MignisConfigException('Bad interface declaration "{0}".'.format(' '.join(x)))
                intf_alias, intf_name, intf_subnet = x[:3]
                intf_options = x[3].split() if len(x) >= 4 else []
                intf_subnet = None if intf_subnet == 'none' else IPv4Network(intf_subnet, strict=True)
                self.intf[intf_alias] = (intf_name, intf_subnet, intf_options)
            self.intf['local'] = ('lo', IPv4Network('127.0.0.0/8', strict=True), [])

            # Read the aliases
            aliases_list = self.config_get('ALIASES', config, split_count=1)
            self.aliases = {}
            for x in aliases_list:
                self.aliases[x[0]] = x[1]

            # Compile aliases regexp
            self.alias_regexp = {}
            for alias, val in iteritems(self.aliases):
                self.alias_regexp[alias] = re.compile('(?<={0}){1}(?={0})'.format('[^a-zA-Z0-9\-_]', alias))

            self.inverse_alias_regexp = {}
            for alias, val in iteritems(self.aliases):
                self.inverse_alias_regexp[val] = re.compile('(?<={0}){1}(?={0})'.format('[^a-zA-Z0-9\-_]', val))

            # Compile the rules regexp
            allowed_chars = '[a-zA-Z0-9\./\*_\-:,\(\) ]'
            self.rule_regexp = re.compile('^({0}+?)(?: +(\[{0}+?\]))? +(/|//|>|<>) +(?:(\[{0}+?\]) +)?({0}*?)(?: +({0}*?))?$'.format(allowed_chars))

            # Read the firewall rules
            if self.debug >= 2:
                print("\n[+] Firewall rules")
            abstract_rules = self.config_get('FIREWALL', config, '\|', 1)
            print(abstract_rules)
            self.fw_rulesdict = self.read_mignis_rules(abstract_rules)

            # Read the default policies
            policies = self.config_get('POLICIES', config, '\|', 1)
            if self.debug >= 2:
                print("\n[+] Policies")
            self.policies_rulesdict = self.read_mignis_rules(policies)
            # Verify that only reject and drop rules were specified
            for k, item in iteritems(self.policies_rulesdict):
                if k not in ['/', '//'] and item != []:
                    raise MignisConfigException('You can only specify reject (//) or drop (/) rules as policies.')
        except MignisConfigException as e:
            raise MignisException(self, 'Error in configuration file:\n' + str(e))

        # Read the custom rules
        try:
            self.custom = self.config_get('CUSTOM', config, split=False)
        except MignisConfigException:
            self.custom = {}
        try:
            self.custom_nft = self.config_get('CUSTOM-NFTABLES', config, split=False)
        except MignisConfigException:
            self.custom_nft = {}


# Argument parsing
def parse_args():
    '''Argument parsing
    '''
    parser = argparse.ArgumentParser(description='A semantic based tool for firewall configuration', add_help=False)
    parser.add_argument('-h', action='help', help='show this help message and exit')
    parser.add_argument('-c', dest='config_file', metavar='filename', help='configuration file', required=True)
    group_action = parser.add_mutually_exclusive_group(required=True)
    group_action.add_argument('-w', dest='write_rules_filename', metavar='filename', help='write the rules to file', required=False)
    group_action.add_argument('-e', dest='execute_rules', help='execute the rules without writing to file', required=False, action='store_true')
    group_action.add_argument('-q', dest='query_rules', metavar='query', help='perform a query over the configuration (unstable)', required=False)
    parser.add_argument('-d', dest='debug', help='set debugging output level (0-2)', required=False, type=int, default=0, choices=range(4))
    parser.add_argument('-n', dest='dryrun', help='do not execute/write the rules (dryrun)', required=False, action='store_true')
    parser.add_argument('-f', dest='force', help='force rule execution or writing', required=False, action='store_true')
    parser.add_argument('--nft', dest='nftables', help='compile rules over nftables instead of iptables', required=False, action='store_true')
    parser.add_argument('-o', dest='optimize', help='try to optimize more aggressively final rules', required=False, action='count')
    # parser.add_argument('-r', dest='reset_script', help='reset script to execute when an error occurs', required=False)
    args = vars(parser.parse_args())
    return args


def main():
    args = parse_args()

    try:
        mignis = Mignis(args['config_file'], args['debug'], args['force'], args['dryrun'], args['write_rules_filename'], args['execute_rules'], args['optimize'], args['nftables'])

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
