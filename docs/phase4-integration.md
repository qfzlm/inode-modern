# Source integration tools

Public installation uses the RPM and `inode-modern-setup`, described in
[installation.md](installation.md). The source-only `integration/install_backend.py`
and recovery helpers support earlier development installations. They are not RPM
installation entry points and must not be run over an active installation casually.

The security boundaries and dynamic system identities are documented in
[security.md](security.md). Runtime evidence, snapshots and recovery bundles are
local administrative data and are excluded from public source distributions.
