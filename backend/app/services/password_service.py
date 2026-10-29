"""Secure password hashing and verification using Argon2id via passlib.

Argon2id is the OWASP-recommended algorithm (winner of the Password Hashing
Competition). It provides memory-hardness, time-hardness, and parallelism
resistance against GPU / ASIC brute-force attacks.

Configuration follows OWASP minimum recommendations:
  - Memory: 19 MB (19456 KiB)
  - Iterations: 2
  - Parallelism: 1
"""

from __future__ import annotations

from passlib.context import CryptContext

# Single global context — CryptContext is thread-safe.
# We mark bcrypt as deprecated so any pre-existing bcrypt hashes are
# automatically re-hashed on next login without user impact.
_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    # Argon2 parameters (OWASP recommended minimums)
    argon2__memory_cost=19456,  # 19 MiB
    argon2__time_cost=2,
    argon2__parallelism=1,
)


class PasswordService:
    """Stateless service for password hashing and verification."""

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """Return an Argon2id hash of *plain_password*.

        The returned string is self-describing (contains algorithm, params,
        and salt) so no external salt storage is needed.
        """
        return _pwd_context.hash(plain_password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Return True iff *plain_password* matches *hashed_password*.

        If the stored hash uses a deprecated algorithm (e.g. bcrypt) or
        weaker parameters, passlib also sets ``needs_update=True`` on the
        CryptContext — callers should re-hash on successful verification.
        """
        return _pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """Return True if *hashed_password* should be rehashed.

        Use this after ``verify_password`` succeeds to proactively upgrade
        legacy hashes without forcing users to change passwords.
        """
        return _pwd_context.needs_update(hashed_password)
