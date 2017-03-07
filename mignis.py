#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
mignis.py is a semantic based tool for firewall configuration.
For usage instructions type:
$ ./mignis.py -h
'''

import argparse
import bisect
import os
import pprint
import re
import sys
import tempfile
import traceback

from collections import Counter, OrderedDict
from ipaddr import AddressValueError, IPv4Address, IPv4Network
from ipaddr_ext import IPv4Range
from itertools import product


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
        }

    def __repr__(self):
        return pprint.pformat(self.params)

    @staticmethod
    def ruletype_str(ruletype):
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
                        #'-s|--source|-d|--destination|'
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
        return (alias, intf, ip, port)

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

    def _format_intfip(self, srcdst, direction, params, iponly=False, portonly=False):
        '''Given 'srcdst' (which specifies if we want a source (s) or destination (d) filter type),
        converts the given address (which may be any of: alias, interface, ip, port) to a string ready for filtering in the form
        '-[io] intf -[ds] ip --[sd]port port'.
        The address is get by using '<direction>_ip', where direction can be any of 'from', 'to' or 'nat'.
        If iponly is specified, an IP address is returned instead of an interface.
        If portonly is specified, no interface/ip filters are added.
        '''
        intf_alias = '{0}_alias'.format(direction)
        intf = '{0}_intf'.format(direction)
        ip = '{0}_ip'.format(direction)
        port = '{0}_port'.format(direction)
        io = 'i' if srcdst == 's' else 'o'

        r = ''
        if not portonly:
            if params[ip]:
                # If there is an IP, we use that instead of the interface as it's more specific
                if isinstance(params[ip], IPv4Range):
                    srcdst_long = 'src' if srcdst == 's' else 'dst'
                    r = '-m iprange --{0}-range {1}'.format(srcdst_long, params[ip])
                else:
                    r = '-{0} {1}'.format(srcdst, params[ip])
            elif iponly:
                # We need to return an IP address instead of the interface,
                # but since no IP was explicitly specified, we have to return the subnet
                if params[intf_alias]:
                    subnet = self.mignis.intf[params[intf_alias]][1]
                    r = '-{0} {1}'.format(srcdst, str(subnet))
                else:
                    r = ''
            elif params[intf]:
                # If there is no IP, we use the interface
                r = '-{0} {1}'.format(io, params[intf])
            else:
                # If there is no IP or interface, we don't add any filter
                r = ''

        if params[port]:
            r += ' --{0}port {1}'.format(srcdst, ':'.join(map(str, params[port])))

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
            raise RuleException('Key error: invalid rule type \'{0}\'.'.format(self.params['rtype']))

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
    def _format_protocol(params):
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
    def format_rule(fmt, params):
        if 'abstract' in params:
            # Escape the " character
            params['rule_escaped'] = params['abstract'].replace('"', '\\"')
            fmt += ' -m comment --comment "{rule_escaped}"'
        params['proto'] = Rule._format_protocol(params)
        rule = re.sub(' +', ' ', fmt.format(**params))
        return rule

    def _forward(self, params, flip=False):
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

    def _snat(self, params, masquerade=False):
        '''Translation for ">" in the case of a SNAT
        '''
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

    def _dnat(self, params):
        '''Translation for ">" in the case of a DNAT
        '''
        rules = []
        if re.search('(^| )-m state ', params['filters']):
            self.mignis.warning('Inspectioning the state in DNAT might corrupt the rule.' +
                                'Use it only if you know what you\'re doing.\n- {0}'.format(params['abstract']))

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
        return rules
    ##


class MignisException(Exception):

    def __init__(self, mignis, message):
        Exception.__init__(self, message)
        # mignis.reset_iptables(False)


class MignisConfigException(Exception):
    pass


class Mignis:
    old_rules = []

    '''
    intf contains the alias/interface/subnet mapping for each interface.
    An example of how its structure looks like:
    {
        'lan': ('eth0', IPv4Network('10.0.0.0/24')),
        'ext': ('eth1', IPv4Network('0.0.0.0/0'))
    }
    '''
    intf = {}
    # Rules to be executed, as strings, in the correct order
    iptables_rules = []

    def __init__(self, config_file, debug, force, dryrun, write_rules_filename, execute_rules, flush):
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

    def execute(self, cmd):
        '''Execute the command s only if we are not in dryrun mode
        '''
        # TODO: use subprocess.check_call with try/except in place of system
        if not self.dryrun:
            if self.debug >= 2:
                print('COMMAND: ' + cmd)
            ret = os.system(cmd)
            if ret:
                raise MignisException(self, 'Command execution error (code: {0}).'.format(ret))

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
        options = ' '
        if self.dryrun or force_dryrun:
            options += '--test '

        try:
            # Execute the rules
            self.execute('iptables-restore' + options + temp_file)
        except MignisException as e:
            raise MignisException(
                self, str(e) + '\nThe temporary file which generated the error is stored in "{0}"'.format(temp_file))

    def write_rules(self, filename, fd=None):
        if self.dryrun:
            return

        if fd:
            f = os.fdopen(fd, 'w')
        else:
            if not self.force and os.path.exists(filename):
                raise MignisException(self, 'The file already exists, use -f to overwrite.')
            f = open(filename, 'w')

        if self.flush:
            # We just need to write the rules to file
            for rule in self.iptables_rules:
                f.write(rule.strip() + '\n')
        else:
            # Split the rules in filter, nat and mangle tables
            separators = '[^a-zA-Z0-9\-_]'
            rules = self.iptables_rules[:]
            tables = {'filter': [], 'nat': [], 'mangle': []}
            for table, table_opt in [
                    ('nat', '(?:\A|{0})(-t nat)(?:\Z|{0})'.format(separators)),
                    ('mangle', '(?:\A|{0})(-t mangle)(?:\Z|{0})'.format(separators))]:
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

    def apply_rules(self):
        print('\n[*] Applying rules')
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
                    execute = ''
                    print('')
                    while execute not in ['y', 'n']:
                        if sys.version_info > (3,):
                            execute = input('Apply the rules? [y|n]: ').lower()
                        else:
                            execute = raw_input('Apply the rules? [y|n]: ').lower()
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

    def add_iptables_rule(self, r, params=None):
        if params:
            r = Rule.format_rule(r, params)
        if self.debug >= 1:
            print('iptables ' + r)
        self.iptables_rules.append(r)

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
        for i_alias, (i_intf, i_subnet, i_options) in self.intf.items():
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
                params = {'subnet': subnet, 'abstract': 'bind any ip to intf {0}'.format(subnet)}
                if ipsub != 'local':
                    # We exclude all the source IPs defined for the other interfaces
                    for other_ipsub in self.intf.keys():
                        # Skip if itself
                        if other_ipsub == ipsub:
                            continue
                        other_subnet, other_ip, other_options = self.intf[other_ipsub]
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

        # Compile the regular expressions
        regexp_alias = {}
        for alias in self.aliases.keys():
            for switch in ['-d ', '-s ', '--destination ', '--source ']:
                regexp_alias.setdefault(alias, []).append(
                    re.compile('(?<={0}){1}(?={2})'.format(switch, alias, '[^a-zA-Z0-9\-_]')))
        regexp_intf = {}
        for alias in self.intf:
            for switch in ['-i ', '-o ', '--in-interface ', '--out-interface ']:
                regexp_intf.setdefault(alias, []).append(
                    re.compile('(?<={0}){1}(?={2})'.format(switch, alias, '[^a-zA-Z0-9\-_]')))

        # For each rule, search and replace aliases recursively
        for rule in self.custom:
            replace_again = True
            while replace_again:
                replace_again = False
                for alias, val in self.aliases.items():
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
                r = tuple(map(lambda x: tuple(map(lambda x: x.strip(), re.split(split_separator, x, split_count))), r))
            return r
        else:
            return None

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
            ports = tuple(map(int, r[1].split('-')))
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
        rules = tuple(map(lambda x: re.split(', *', x), filter(None, re.split('[()]', rule))))

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
                        else:
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
            return open(filename).read().strip()
        except:
            raise MignisConfigException('Unable to read file "{0}" for inclusion.'.format(filename))

    def read_config(self):
        '''Parses the configuration file and populates the rulesdict dictionary
        '''
        try:
            print("[*] Reading the configuration")
            self.config_dir = os.path.dirname(self.config_file)
            config = open(self.config_file).read()

            # Execute the @include directives (recursively)
            old_config = ''
            while config != old_config:
                old_config = config
                config = re.sub('(?<=\n)@include[ \t]+(.*?)(?=\n)', self.config_include, config)

            # Replace every sequence of tabs and spaces with a single space
            config = re.sub('[ \t]+', ' ', config)

            # Split by section
            config = re.split('(OPTIONS|INTERFACES|ALIASES|FIREWALL|POLICIES|CUSTOM)\n', config)[1:]
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
            for x in tuple(intf):
                if 3 > len(x) > 4:
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
            for alias, val in self.aliases.items():
                self.alias_regexp[alias] = re.compile('(?<={0}){1}(?={0})'.format('[^a-zA-Z0-9\-_]', alias))

            self.inverse_alias_regexp = {}
            for alias, val in self.aliases.items():
                self.inverse_alias_regexp[val] = re.compile('(?<={0}){1}(?={0})'.format('[^a-zA-Z0-9\-_]', val))

            # Compile the rules regexp
            allowed_chars = '[a-zA-Z0-9\./\*_\-:,\(\) ]'
            self.rule_regexp = re.compile(
                '^({0}+?)(?: +(\[{0}+?\]))? +(/|//|>|<>) +(?:(\[{0}+?\])'
                ' +)?({0}*?)(?: +({0}*?))?$'.format(allowed_chars))

            # Read the firewall rules
            if self.debug >= 2:
                print("\n[+] Firewall rules")
            abstract_rules = self.config_get('FIREWALL', config, '\|', 1)
            self.fw_rulesdict = self.read_mignis_rules(abstract_rules)

            # Read the default policies
            policies = self.config_get('POLICIES', config, '\|', 1)
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
    action_group.add_argument('-F', '--flush', dest='flush', help='flush iptables ruleset',
                              required=False, action='store_true')
    action_group.add_argument('-c', '--config', dest='config_file', metavar='filename',
                              help='read mignis rules from file', required=False)
    config_group = parser.add_argument_group('options for --config/-c')
    config_group = config_group.add_mutually_exclusive_group(required=False)
    config_group.add_argument('-w', '--write', dest='write_rules_filename', metavar='filename',
                              help='write the rules to file', required=False)
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
