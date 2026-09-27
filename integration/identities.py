"""Resolve dedicated service accounts through NSS; never assume numeric IDs."""
import grp
import os
import pwd

ROLES = ('inode-modern-broker', 'inode-modern-engine', 'inode-modern-mon')

class IdentityError(RuntimeError):
    pass


def resolve_identities(allow_missing=False):
    users, groups = pwd.getpwall(), grp.getgrall()
    resolved = {}
    for name in ROLES:
        us = [u for u in users if u.pw_name == name]
        gs = [g for g in groups if g.gr_name == name]
        if not us and not gs and allow_missing:
            for lookup in (pwd.getpwnam, grp.getgrnam):
                try:
                    lookup(name)
                except KeyError:
                    continue
                raise IdentityError('Role identity hidden from NSS enumeration')
            if any(name in g.gr_mem for g in groups):
                raise IdentityError('Missing role has supplementary memberships')
            continue
        if len(us) != 1 or len(gs) != 1:
            raise IdentityError('Missing, duplicate or partial role identity')
        u, g = us[0], gs[0]
        if (u.pw_uid <= 0 or g.gr_gid <= 0 or u.pw_gid != g.gr_gid
                or u.pw_shell not in ('/usr/bin/nologin', '/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false')
                or u.pw_dir not in ('/', '/nonexistent')
                or any(member != name for member in g.gr_mem)
                or sum(v.pw_uid == u.pw_uid for v in users) != 1
                or sum(v.gr_gid == g.gr_gid for v in groups) != 1):
            raise IdentityError('Role identity is shared, privileged or login-capable')
        if (pwd.getpwnam(name) != u or pwd.getpwuid(u.pw_uid) != u
                or grp.getgrnam(name) != g or grp.getgrgid(g.gr_gid) != g):
            raise IdentityError('Inconsistent NSS role identity')
        if (any(v.pw_name != name and v.pw_gid == g.gr_gid for v in users)
                or any(v.gr_gid != g.gr_gid and name in v.gr_mem for v in groups)
                or set(os.getgrouplist(name, g.gr_gid)) != {g.gr_gid}):
            raise IdentityError('Role group shared or supplementary membership present')
        resolved[name] = (u.pw_uid, g.gr_gid)
    return resolved


def check_identities(allow_missing=False):
    resolved = resolve_identities(allow_missing)
    return [name for name in ROLES if name not in resolved]
