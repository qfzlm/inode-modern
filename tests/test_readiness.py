import copy
import json
import unittest
from unittest.mock import patch
from tools import readiness as r


class ReadinessTests(unittest.TestCase):
    def poll(self, failures, timeout=5):
        now = [0.0]
        saved = []
        def sample(deadline):
            index = min(int(now[0]), len(failures)-1)
            return {'started_monotonic': now[0], 'finished_monotonic': now[0],
                    'checks': {k: {'ok': k not in failures[index], 'data': {},
                                  'started_monotonic': now[0], 'finished_monotonic': now[0]} for k in r.CHECKS}}
        result = r.poll_readiness(sample, lambda p: saved.append(copy.deepcopy(p)), timeout, 1,
                                  clock=lambda: now[0], pause=lambda t: now.__setitem__(0, now[0]+t))
        self.assertEqual(saved[-1], result)
        self.assertEqual(len(result['samples']), len([p for p in saved if not p.get('timed_out')]))
        return result

    def test_immediate_ready_requires_confirmation(self):
        p = self.poll([set()])
        self.assertTrue(p['all_passed'])
        self.assertEqual(len(p['samples']), 2)
        self.assertEqual(p['ready_monotonic'], 1)

    def test_ipv4_after_authentication(self):
        p = self.poll([{'ipv4'}, {'ipv4'}, set()])
        self.assertEqual(p['authentication_success_monotonic'], 0)
        self.assertEqual(p['first_green_monotonic']['ipv4'], 2)
        self.assertEqual(p['ready_monotonic'], 3)

    def test_gateway_delay(self):
        p = self.poll([{'gateway', 'gateway_ping'}, set()])
        self.assertTrue(p['all_passed'])
        self.assertEqual(p['first_green_monotonic']['gateway'], 1)

    def test_external_delay(self):
        p = self.poll([{'external_ping'}, {'external_ping'}, set()])
        self.assertEqual(p['first_green_monotonic']['external_ping'], 2)

    def test_permanent_failure_retains_every_sample(self):
        p = self.poll([{'external_ping'}])
        self.assertFalse(p['all_passed'])
        self.assertTrue(p['timed_out'])
        self.assertEqual(len(p['samples']), 5)
        self.assertEqual(p['last_failed_conditions'], ['external_ping'])
        self.assertEqual(p['finished_monotonic'], 5)

    def test_transient_all_green_is_not_pass(self):
        p = self.poll([{'ipv4'}, set(), {'external_ping'}])
        self.assertFalse(p['all_passed'])
        self.assertEqual(p['first_all_green_monotonic'], 1)
        self.assertIsNone(p['ready_monotonic'])

    def test_different_green_items_not_combined_across_samples(self):
        p = self.poll([{'ipv4'}, {'external_ping'}, {'ipv4'}, {'external_ping'}])
        self.assertFalse(p['all_passed'])

    def test_deadline_overrun_cannot_pass(self):
        now = [0]
        def sample(deadline):
            now[0] = deadline + 1
            return {'finished_monotonic': now[0], 'checks': {k: {'ok': True, 'finished_monotonic': now[0]} for k in r.CHECKS}}
        p = r.poll_readiness(sample, lambda p: None, 2, clock=lambda: now[0])
        self.assertFalse(p['all_passed'])

    def test_real_sampler_is_independent_and_secret_safe(self):
        secret = 'CREDENTIAL_SENTINEL_012345'
        calls = []
        def command(args, **kw):
            from subprocess import CompletedProcess
            calls.append(args)
            self.assertGreater(kw['timeout'], 0)
            if 'addr' in args:
                return CompletedProcess(args, 0, json.dumps([{'addr_info':[{'family':'inet','local':'10.0.0.2','prefixlen':24}], 'secret':secret}]), secret)
            if 'route' in args:
                return CompletedProcess(args, 0, json.dumps([{'dst':'default','gateway':'10.0.0.1','secret':secret}]), secret)
            count = args[args.index('-c')+1]
            return CompletedProcess(args, 0, f'{count} packets transmitted, {count} received, 0% packet loss\n{secret}', secret)
        def auth(deadline):
            return {'state':2, 'result':0, 'password':secret}
        def pair(deadline):
            raise RuntimeError(secret)
        with patch.object(r.subprocess, 'run', side_effect=command), patch.object(r.Path, 'read_text', side_effect=['1','up']):
            p = r.sample_readiness(r.time.monotonic()+40, auth, pair, '10.0.0.1')
        self.assertNotIn(secret, json.dumps(p))
        self.assertTrue(p['checks']['authentication']['ok'])
        self.assertFalse(p['checks']['vendor_pair']['ok'])
        self.assertEqual(set(p['checks']), set(r.CHECKS))
        self.assertEqual(len(calls), 4)
        for cmd in calls[2:]:
            self.assertEqual(cmd[cmd.index('-I')+1], 'enp5s0')
        for item in p['checks'].values():
            self.assertLessEqual(item['started_monotonic'], item['finished_monotonic'])

    def test_missing_ping_statistics_fail_closed(self):
        from subprocess import CompletedProcess
        with patch.object(r.subprocess, 'run', return_value=CompletedProcess([],0,'unparseable','')), patch.object(r.Path, 'read_text', side_effect=['0','down']):
            p = r.sample_readiness(r.time.monotonic()+40, lambda d:{'state':2,'result':0}, lambda d:{'legal':True,'engine_pid':1,'watchdog_pid':2}, '10.0.0.1')
        self.assertFalse(p['checks']['gateway_ping']['ok'])
        self.assertFalse(p['checks']['carrier']['ok'])
        self.assertTrue(p['checks']['vendor_pair']['ok'])
