import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from mignis import Mignis, MignisException


CONFIG_TEMPLATE = '''\
OPTIONS
default_rules no
logging no

INTERFACES
lan eth0 10.0.0.0/24
ext eth1 0.0.0.0/0 wan

ALIASES
client_a 10.0.0.10
client_b 10.0.0.11

FIREWALL
lan > ext

POLICIES
* / *

{limits_section}
CUSTOM
'''


class TrafficShapingTests(unittest.TestCase):
    def make_mignis(self, limits=None):
        if limits is None:
            limits_section = ''
        else:
            limits_section = 'LIMITS\n' + limits.strip() + '\n\n'

        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        config_path = os.path.join(temporary_directory.name, 'test.config')
        with open(config_path, 'w') as config_file:
            config_file.write(CONFIG_TEMPLATE.format(limits_section=limits_section))

        with contextlib.redirect_stdout(io.StringIO()):
            mignis = Mignis(
                config_path,
                debug=0,
                force=False,
                dryrun=False,
                write_rules_filename=None,
                execute_rules=False,
                flush=False,
            )
            mignis.all_rules()
        return mignis, temporary_directory.name

    def test_configuration_without_limits_has_no_tc_output(self):
        mignis, _ = self.make_mignis()

        self.assertEqual([], mignis.traffic_limits)
        self.assertEqual([], mignis.tc_rules)
        self.assertFalse(any('MIGNIS_TC' in rule for rule in mignis.iptables_rules))

    def test_generates_htb_classes_and_packet_mark(self):
        mignis, _ = self.make_mignis('''
on ext egress * > * 20mbit
on ext egress client_a > * 5mbit
''')

        self.assertIn(
            'qdisc replace dev eth1 root handle 1d00: htb default 2',
            mignis.tc_rules,
        )
        self.assertIn(
            'class replace dev eth1 parent 1d00:1 classid 1d00:10 '
            'htb rate 1kbit ceil 5mbit',
            mignis.tc_rules,
        )
        self.assertIn(
            'filter replace dev eth1 parent 1d00: protocol ip priority 10 '
            'handle 0x00100000/0xffff0000 fw classid 1d00:10',
            mignis.tc_rules,
        )
        self.assertIn(
            '-t mangle -A MIGNIS_TC -o eth1 -s 10.0.0.10 '
            '-j MARK --set-xmark 0x00100000/0xffff0000',
            mignis.iptables_rules,
        )

    def test_destination_limit_uses_output_interface_and_destination(self):
        mignis, _ = self.make_mignis('''
on lan egress * > * 50mbit
on lan egress * > client_a 8mbit
''')

        self.assertIn(
            '-t mangle -A MIGNIS_TC -o eth0 -d 10.0.0.10 '
            '-j MARK --set-xmark 0x00100000/0xffff0000',
            mignis.iptables_rules,
        )

    def test_rejects_missing_direction(self):
        with self.assertRaisesRegex(
                MignisException,
                r'Expected: on INTERFACE \(egress\|ingress\)'):
            self.make_mignis('on ext * > * 20mbit')

    def test_generates_ifb_redirect_and_flower_for_ingress(self):
        mignis, _ = self.make_mignis('''
on lan ingress * > * 12mbit
on lan ingress client_a > * 3mbit
''')
        ifb = Mignis._ifb_name('eth0')

        self.assertIn(
            f'filter replace dev eth0 ingress protocol all priority 49152 '
            f'handle 1 matchall action mirred egress redirect dev {ifb}',
            mignis.tc_rules,
        )
        self.assertIn(
            f'qdisc replace dev {ifb} root handle 1d00: htb default 2',
            mignis.tc_rules,
        )
        self.assertIn(
            f'filter replace dev {ifb} parent 1d00: protocol ip priority 10 '
            'flower src_ip 10.0.0.10/32 classid 1d00:10',
            mignis.tc_rules,
        )
        self.assertFalse(any('MIGNIS_TC' in rule for rule in mignis.iptables_rules))

    def test_same_selector_can_be_shaped_in_both_directions(self):
        mignis, _ = self.make_mignis('''
on lan egress * > * 20mbit
on lan egress client_a > * 5mbit
on lan ingress * > * 12mbit
on lan ingress client_a > * 3mbit
''')

        self.assertEqual(2, len(mignis.traffic_limit_groups))
        self.assertEqual(
            {'egress', 'ingress'},
            {limit.direction for limit in mignis.traffic_limits},
        )

    def test_flow_output_is_order_independent(self):
        first, _ = self.make_mignis('''
on ext egress * > * 20mbit
on ext egress client_b > * 8mbit
on ext egress client_a > * 5mbit
''')
        second, _ = self.make_mignis('''
on ext egress client_a > * 5mbit
on ext egress * > * 20mbit
on ext egress client_b > * 8mbit
''')

        self.assertEqual(first.tc_rules, second.tc_rules)
        first_marks = [rule for rule in first.iptables_rules if '--set-xmark' in rule]
        second_marks = [rule for rule in second.iptables_rules if '--set-xmark' in rule]
        self.assertEqual(first_marks, second_marks)

    def test_rejects_flow_limit_without_aggregate_limit(self):
        with self.assertRaisesRegex(MignisException, 'no aggregate'):
            self.make_mignis('on ext egress client_a > * 5mbit')

    def test_aggregate_limit_is_required_in_the_same_direction(self):
        with self.assertRaisesRegex(MignisException, 'same direction'):
            self.make_mignis('''
on lan egress * > * 20mbit
on lan ingress client_a > * 3mbit
''')

    def test_rejects_flow_limit_above_aggregate_limit(self):
        with self.assertRaisesRegex(MignisException, 'exceeds the aggregate'):
            self.make_mignis('''
on ext egress * > * 5mbit
on ext egress client_a > * 10mbit
''')

    def test_rejects_overlapping_flow_limits(self):
        with self.assertRaisesRegex(MignisException, 'Overlapping traffic limits'):
            self.make_mignis('''
on ext egress * > * 20mbit
on ext egress lan > * 10mbit
on ext egress client_a > * 5mbit
''')

    def test_rejects_invalid_rate(self):
        with self.assertRaisesRegex(MignisException, 'Invalid traffic limit rate'):
            self.make_mignis('on ext egress * > * 20megabits')

    def test_rejects_special_local_selector(self):
        with self.assertRaisesRegex(MignisException, 'special "local" alias'):
            self.make_mignis('''
on ext egress * > * 20mbit
on ext egress local > * 5mbit
''')

    def test_tc_batch_uses_replace_for_deterministic_updates(self):
        mignis, _ = self.make_mignis('''
on ext egress * > * 20mbit
on ext egress client_a > * 5mbit
''')

        self.assertTrue(all(' add ' not in f' {rule} ' for rule in mignis.tc_rules))
        self.assertTrue(any(rule.startswith('class replace ') for rule in mignis.tc_rules))
        self.assertTrue(any(rule.startswith('filter replace ') for rule in mignis.tc_rules))

    def test_write_creates_tc_sidecar_only_when_needed(self):
        mignis, temporary_directory = self.make_mignis('''
on ext egress * > * 20mbit
on ext egress client_a > * 5mbit
''')
        output_path = os.path.join(temporary_directory, 'rules.iptables')

        output_files = mignis.write_all_rules(output_path)

        self.assertEqual([output_path, output_path + '.tc'], output_files)
        self.assertTrue(os.path.exists(output_path))
        self.assertTrue(os.path.exists(output_path + '.tc'))
        with open(output_path + '.tc') as tc_file:
            self.assertEqual(mignis.tc_rules, tc_file.read().splitlines())

    def test_write_creates_ingress_setup_runner(self):
        mignis, temporary_directory = self.make_mignis('''
on lan ingress * > * 12mbit
on lan ingress client_a > * 3mbit
''')
        output_path = os.path.join(temporary_directory, 'rules.iptables')
        ifb = Mignis._ifb_name('eth0')

        output_files = mignis.write_all_rules(output_path)

        self.assertEqual(
            [output_path, output_path + '.tc', output_path + '.tc.sh'],
            output_files,
        )
        self.assertTrue(os.access(output_path + '.tc.sh', os.X_OK))
        with open(output_path + '.tc.sh') as runner_file:
            runner = runner_file.read()
        self.assertIn(f'ip link add name {ifb} type ifb', runner)
        self.assertIn('tc qdisc add dev eth0 clsact', runner)
        self.assertIn('exec tc -batch "$script_directory"/rules.iptables.tc', runner)

    def test_instances_do_not_share_generated_rules(self):
        shaped, _ = self.make_mignis('on ext egress * > * 20mbit')
        unshaped, _ = self.make_mignis()

        self.assertTrue(shaped.tc_rules)
        self.assertEqual([], unshaped.tc_rules)
        self.assertFalse(any('MIGNIS_TC' in rule for rule in unshaped.iptables_rules))

    def test_removes_stale_mignis_qdisc_from_saved_state(self):
        mignis, temporary_directory = self.make_mignis()
        state_path = os.path.join(temporary_directory, 'tc-state.json')
        with open(state_path, 'w') as state_file:
            state_file.write('{"version": 1, "interfaces": ["eth1"]}\n')

        executed = []
        mignis.execute = lambda command, capture_output=False: executed.append(command)
        mignis._root_qdisc = lambda interface: {
            'kind': 'htb',
            'handle': '1d00:',
            'root': True,
        }

        with mock.patch.dict(os.environ, {'MIGNIS_TC_STATE_FILE': state_path}):
            mignis.apply_tc_rules()

        self.assertIn(['tc', 'qdisc', 'del', 'dev', 'eth1', 'root'], executed)
        self.assertFalse(os.path.exists(state_path))

    def test_reapplication_rebuilds_existing_mignis_qdisc(self):
        mignis, temporary_directory = self.make_mignis('''
on ext egress * > * 20mbit
on ext egress client_a > * 5mbit
''')
        state_path = os.path.join(temporary_directory, 'tc-state.json')
        executed = []
        mignis.execute = lambda command, capture_output=False: executed.append(command)
        mignis._root_qdisc = lambda interface: {
            'kind': 'htb',
            'handle': '1d00:',
            'root': True,
        }

        with mock.patch.dict(os.environ, {'MIGNIS_TC_STATE_FILE': state_path}):
            mignis.apply_tc_rules()

        self.assertEqual(
            ['tc', 'qdisc', 'del', 'dev', 'eth1', 'root'],
            executed[0],
        )
        self.assertEqual(['tc', '-batch'], executed[1][:2])
        self.assertTrue(os.path.exists(state_path))


if __name__ == '__main__':
    unittest.main()
