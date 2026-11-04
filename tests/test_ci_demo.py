"""Temporary: proves CI turns red on a failing test. Reverted in the next commit."""


def test_ci_catches_failures():
    assert 1 + 1 == 3, "deliberate failure to show CI goes red"
