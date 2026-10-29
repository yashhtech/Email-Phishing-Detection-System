"""JWT token creation, validation, and claims management.

Token strategy
--------------
* **Access tokens**: short-lived (default 15 min), signed HS256 JWT, delivered
  as a JSON body field (Bearer token in Authorization header).
* **Refresh tokens**: longer-lived (default 7 days), stored server-side in
  Redis after issue so they can be revoked on logout.  The JWT itself carries
  a unique ``jti`` (JWT ID) that is used as the Redis key prefix.

Token payload (claims)
-----------------------
sub  — user UUID (as string)
role — UserRoleType value
org  — organization UUID (as string)
jti  — UUID v4 token identifier (used for revocation)
type — "access" | "refresh"
iat  — issued-at (Unix timestamp)
exp  — expiry (Unix timestamp)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from jose import JWTError, jwt

from app.infrastructure.config.settings import Settings


class TokenClaims:
    """Parsed and validated JWT claims container."""

    __slots__ = ("exp", "jti", "org_id", "role", "token_type", "user_id")

    def __init__(
        self,
        user_id: uuid.UUID,
        role: str,
        org_id: uuid.UUID,
        jti: uuid.UUID,
        token_type: Literal["access", "refresh"],
        exp: datetime,
    ) -> None:
        self.user_id = user_id
        self.role = role
        self.org_id = org_id
        self.jti = jti
        self.token_type = token_type
        self.exp = exp

    def is_expired(self) -> bool:
        """Return True if this token has passed its expiry time."""
        return datetime.now(UTC) > self.exp


class TokenService:
    """Stateless JWT factory and validator.

    Instantiate once at application startup and inject via DI.
    """

    def __init__(self, settings: Settings) -> None:
        self._secret = settings.jwt_secret_key.get_secret_value()
        self._algorithm = settings.jwt_algorithm
        self._access_ttl = timedelta(minutes=settings.access_token_expire_minutes)
        self._refresh_ttl = timedelta(days=settings.refresh_token_expire_days)

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    def create_access_token(
        self,
        user_id: uuid.UUID,
        role: str,
        org_id: uuid.UUID,
    ) -> tuple[str, uuid.UUID, datetime]:
        """Create and sign a new access token.

        Returns:
            (encoded_jwt, jti, expiry_datetime)
        """
        return self._create_token(user_id, role, org_id, "access", self._access_ttl)

    def create_refresh_token(
        self,
        user_id: uuid.UUID,
        role: str,
        org_id: uuid.UUID,
    ) -> tuple[str, uuid.UUID, datetime]:
        """Create and sign a new refresh token.

        Returns:
            (encoded_jwt, jti, expiry_datetime)
        """
        return self._create_token(user_id, role, org_id, "refresh", self._refresh_ttl)

    def _create_token(
        self,
        user_id: uuid.UUID,
        role: str,
        org_id: uuid.UUID,
        token_type: Literal["access", "refresh"],
        ttl: timedelta,
    ) -> tuple[str, uuid.UUID, datetime]:
        now = datetime.now(UTC)
        exp = now + ttl
        jti = uuid.uuid4()

        payload: dict[str, Any] = {
            "sub": str(user_id),
            "role": role,
            "org": str(org_id),
            "jti": str(jti),
            "type": token_type,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }

        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        return token, jti, exp

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def decode_token(
        self,
        token: str,
        *,
        expected_type: Literal["access", "refresh"] = "access",
    ) -> TokenClaims:
        """Decode and validate a JWT.

        Raises:
            ValueError: if the token is invalid, expired, or wrong type.
        """
        try:
            raw: dict[str, Any] = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
            )
        except JWTError as exc:
            raise ValueError(f"Invalid token: {exc}") from exc

        token_type = raw.get("type")
        if token_type != expected_type:
            raise ValueError(f"Wrong token type: expected '{expected_type}', got '{token_type}'")

        try:
            return TokenClaims(
                user_id=uuid.UUID(raw["sub"]),
                role=raw["role"],
                org_id=uuid.UUID(raw["org"]),
                jti=uuid.UUID(raw["jti"]),
                token_type=expected_type,
                exp=datetime.fromtimestamp(raw["exp"], tz=UTC),
            )
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Malformed token payload: {exc}") from exc

    # ------------------------------------------------------------------
    # TTL helpers (used by revocation service)
    # ------------------------------------------------------------------

    @property
    def refresh_ttl_seconds(self) -> int:
        """Return the refresh token TTL in whole seconds."""
        return int(self._refresh_ttl.total_seconds())

    @property
    def access_ttl_seconds(self) -> int:
        """Return the access token TTL in whole seconds."""
        return int(self._access_ttl.total_seconds())
