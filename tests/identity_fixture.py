"""Synthetic role database for tests, never imported by production code."""
from unittest.mock import patch

ROLES = {f'inode-modern-{role}': (number, number) for role, number in
         (('broker', 10000), ('engine', 10001), ('mon', 10002))}

def start_role_fixture(module):
    patches = []
    for name in ('backend','invariants','installer'):
        target = getattr(module, name, None)
        if target is not None and hasattr(target, 'resolve_identities'):
            mock = patch.object(target, 'resolve_identities', return_value=ROLES)
            mock.start(); patches.append(mock)
    return patches
