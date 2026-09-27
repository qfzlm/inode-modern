"""Bounded, evidence-preserving wired convergence checks for rehearsals.

Authentication is one condition, never a substitute for network readiness.
Raw subprocess output, protocol messages and exception text are not artifacts.
"""
import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path

CHECKS = ('carrier', 'ipv4', 'gateway', 'gateway_ping', 'external_ping', 'vendor_pair', 'authentication')


def poll_readiness(sample, save, timeout=40.0, interval=0.5, *, clock=time.monotonic, pause=time.sleep):
    """Require two consecutive complete green samples within the existing 40s budget."""
    if timeout <= 0 or interval <= 0:
        raise ValueError('positive polling budget required')
    start = clock()
    deadline = start + timeout
    report = {'started_monotonic': start, 'deadline_monotonic': deadline,
              'timeout_seconds': timeout, 'required_consecutive': 2, 'samples': [],
              'first_green_monotonic': {}, 'authentication_success_monotonic': None,
              'first_all_green_monotonic': None, 'ready_monotonic': None, 'all_passed': False}
    streak = 0
    while clock() < deadline:
        point = sample(deadline)
        report['samples'].append(point)
        for key in CHECKS:
            item = point['checks'][key]
            if item['ok']:
                report['first_green_monotonic'].setdefault(key, item['finished_monotonic'])
        if point['checks']['authentication']['ok'] and report['authentication_success_monotonic'] is None:
            report['authentication_success_monotonic'] = point['checks']['authentication']['finished_monotonic']
        green = all(point['checks'][k]['ok'] for k in CHECKS) and clock() <= deadline
        if green and report['first_all_green_monotonic'] is None:
            report['first_all_green_monotonic'] = point['finished_monotonic']
        streak = streak + 1 if green else 0
        if streak >= 2:
            report['all_passed'] = True
            report['ready_monotonic'] = clock()
        report['finished_monotonic'] = clock()
        report['last_failed_conditions'] = [k for k in CHECKS if not point['checks'][k]['ok']]
        save(report)  # Persist every sample, including successful and transient green samples.
        if report['all_passed']:
            return report
        remaining = deadline - clock()
        if remaining > 0:
            pause(min(interval, remaining))
    report['timed_out'] = True
    report['finished_monotonic'] = clock()
    save(report)
    return report


def sample_readiness(deadline, authentication, vendor_pair, expected_gateway,
                     interface='enp5s0', external_ip='223.5.5.5'):
    """Callbacks accept the absolute deadline; pair must enforce exact runtime identity.

    All fields are sampled independently even when another condition fails. Each
    subprocess shares the absolute deadline and has a per-command upper bound.
    """
    expected_gateway = str(ipaddress.IPv4Address(expected_gateway))
    external_ip = str(ipaddress.IPv4Address(external_ip))
    if interface != 'enp5s0':
        raise ValueError('unexpected rehearsal interface')
    point = {'started_monotonic': time.monotonic(), 'checks': {}}

    def run(args, seconds=3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=min(seconds, remaining), env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C'})

    def record(key, probe):
        item = {'started_monotonic': time.monotonic(), 'ok': False, 'data': None}
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError
            item['ok'], item['data'] = probe()
        except (TimeoutError, subprocess.TimeoutExpired):
            item['error'] = 'deadline_or_probe_timeout'
        except Exception:
            item['error'] = 'probe_error'  # Deliberately never str(exception).
        item['finished_monotonic'] = time.monotonic()
        point['checks'][key] = item
        return item

    def carrier():
        root = Path('/sys/class/net') / interface
        value = int((root/'carrier').read_text().strip())
        state = (root/'operstate').read_text().strip()
        if value not in (0, 1) or state not in ('unknown', 'notpresent', 'down', 'lowerlayerdown', 'testing', 'dormant', 'up'):
            raise ValueError
        return value == 1 and state == 'up', {'carrier': value, 'operstate': state}

    def ipv4():
        res = run(['ip', '-j', '-4', 'addr', 'show', 'dev', interface])
        if res.returncode:
            raise ValueError
        addresses = []
        for link in json.loads(res.stdout):
            for addr in link.get('addr_info', []):
                if addr.get('family') == 'inet':
                    address = ipaddress.IPv4Interface(f"{addr['local']}/{addr['prefixlen']}")
                    addresses.append(str(address))
        return bool(addresses), {'addresses': addresses}

    def routes():
        res = run(['ip', '-j', '-4', 'route', 'show', 'table', 'all', 'dev', interface])
        if res.returncode:
            raise ValueError
        clean = []
        gateways = []
        for route in json.loads(res.stdout):
            dst = route.get('dst', 'default')
            row = {'dst': 'default' if dst == 'default' else str(ipaddress.IPv4Network(dst, strict=False))}
            for key in ('gateway', 'prefsrc'):
                if key in route:
                    row[key] = str(ipaddress.IPv4Address(route[key]))
            for key in ('metric',):
                if key in route:
                    row[key] = int(route[key])
            # Only enum/integer table names can be recorded, never arbitrary text.
            table = route.get('table', 'main')
            if table in ('main', 'local', 'default') or isinstance(table, int):
                row['table'] = table
            clean.append(row)
            if dst == 'default' and table in ('main', 254) and 'gateway' in row:
                gateways.append(row['gateway'])
        return gateways == [expected_gateway], {'expected_gateway': expected_gateway, 'default_gateways': gateways, 'routes': clean}

    def ping(target, count):
        res = run(['ping', '-n', '-I', interface, '-c', str(count), '-W', '2', target], count * 2 + 1)
        match = re.search(r'(\d+) packets transmitted, (\d+) received,.*?([\d.]+)% packet loss', res.stdout)
        sent, received, loss = (int(match[1]), int(match[2]), float(match[3])) if match else (None, None, None)
        return res.returncode == 0 and sent == received == count and loss == 0, {
            'target': target, 'interface': interface, 'sent': sent, 'received': received,
            'packet_loss_percent': loss, 'returncode': res.returncode}

    def auth():
        data = authentication(deadline)
        state, result = data.get('state'), data.get('result')
        if any(value is not None and (type(value) is not int or not 0 <= value < 2**32) for value in (state, result)):
            raise ValueError
        return state == 2 and result == 0, {'state': state, 'result': result}

    def pair():
        data = vendor_pair(deadline)
        pids = {k: data[k] for k in ('engine_pid', 'watchdog_pid', 'broker_pid') if k in data}
        if not {'engine_pid', 'watchdog_pid'} <= pids.keys() or any(type(v) is not int or v <= 0 for v in pids.values()):
            raise ValueError
        if len(set(pids.values())) != len(pids):
            raise ValueError
        return data.get('legal') is True, {'legal': data.get('legal') is True, **pids}

    record('authentication', auth)
    record('carrier', carrier)
    record('ipv4', ipv4)
    record('gateway', routes)
    record('gateway_ping', lambda: ping(expected_gateway, 2))
    record('external_ping', lambda: ping(external_ip, 3))
    record('vendor_pair', pair)
    point['finished_monotonic'] = time.monotonic()
    return point
