"""Errors the CLI maps to stable exit codes.

Exit codes:
    1 other failures
    2 usage
    3 authentication (password, token, or key file rejected)
    4 policy (expired, open count, or a license looser than the package)
    5 integrity (ciphertext or authenticated metadata failed)
    6 malformed package, license, or state file
"""

from __future__ import annotations


class DrmError(Exception):
    """Expected failure with a message safe to show on a terminal."""

    exit_code = 1


class UsageError(DrmError):
    exit_code = 2


class AuthenticationError(DrmError):
    exit_code = 3


class PolicyError(DrmError):
    exit_code = 4


class IntegrityError(DrmError):
    exit_code = 5


class FormatError(DrmError):
    exit_code = 6
