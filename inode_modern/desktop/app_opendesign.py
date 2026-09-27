"""Opt-in source entry; retains the existing single-instance and Worker wiring."""
from .app import main as desktop_main
from .window_opendesign import Window


def main(argv=None):
    return desktop_main(argv, window_factory=Window)


if __name__ == '__main__':
    raise SystemExit(main())
