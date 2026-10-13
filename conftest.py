"""Project-wide pytest configuration.

Defaults pytest's tmp_path/tmp_path_factory base directory to a
project-local folder instead of the OS global temp directory. Found
necessary on this Windows dev machine: the default
%TEMP%\\pytest-of-<user> directory can end up access-denied (a stale
lock from another process, antivirus scan, etc.), which crashes test
collection with a PermissionError that reads like a test bug rather
than an environment one - this is why `pytest tests/` sometimes needs
`--basetemp` passed explicitly on Windows here. A project-local
directory sidesteps that category of failure entirely; explicitly
passing --basetemp still overrides this default.
"""
from pathlib import Path


def pytest_configure(config):
    if config.option.basetemp is None:
        local_tmp = Path(__file__).resolve().parent / ".pytest_tmp"
        local_tmp.mkdir(exist_ok=True)
        config.option.basetemp = local_tmp
