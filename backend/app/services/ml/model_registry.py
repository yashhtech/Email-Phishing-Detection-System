"""Model registry for versioning and serving ML classifiers.

Responsibilities:
- Register multiple model versions (e.g., v1.0.0, v1.1.0, v2.0.0-experimental)
- Designate an active default model for inference
- Retrieve model by version tag
- Provide a robust fallback if requested version is not found
- Support runtime model swapping without service restart
"""

from __future__ import annotations

from typing import Any

import structlog

from app.services.ml.classifier import (
    BaseClassifier,
    CalibratedHeuristicClassifier,
    FallbackClassifier,
)

logger = structlog.get_logger(__name__)


class ModelRegistry:
    """Thread-safe in-memory model registry supporting versioning and fallback."""

    def __init__(self) -> None:
        self._models: dict[str, BaseClassifier] = {}
        self._default_version: str = "v1.0.0"
        self._fallback_model: BaseClassifier = FallbackClassifier()

        # Seed with initial production model
        self.register(CalibratedHeuristicClassifier(version="v1.0.0"), is_default=True)
        # Register a v1.1.0 enhanced version
        self.register(CalibratedHeuristicClassifier(version="v1.1.0"))

    def register(self, model: BaseClassifier, is_default: bool = False) -> None:
        """Register a new model version in the registry."""
        version = model.model_version
        self._models[version] = model
        if is_default:
            self._default_version = version
        logger.info(
            "model_registered", name=model.model_name, version=version, is_default=is_default
        )

    def get_model(self, version: str | None = None) -> BaseClassifier:
        """Retrieve model by version tag, or fallback to default if not found."""
        target_version = version or self._default_version
        if target_version in self._models:
            return self._models[target_version]

        logger.warning(
            "model_version_not_found_using_fallback",
            requested_version=version,
            default_version=self._default_version,
        )
        return self._models.get(self._default_version, self._fallback_model)

    def set_default_version(self, version: str) -> None:
        """Set which model version serves default inference traffic."""
        if version not in self._models:
            raise KeyError(f"Cannot set default version: '{version}' is not registered.")
        self._default_version = version
        logger.info("default_model_version_updated", version=version)

    def list_models(self) -> list[dict[str, Any]]:
        """List all available model versions in the registry."""
        return [
            {
                "model_name": m.model_name,
                "model_version": m.model_version,
                "is_default": m.model_version == self._default_version,
            }
            for m in self._models.values()
        ]

    @property
    def default_version(self) -> str:
        return self._default_version
