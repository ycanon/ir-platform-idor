"""Estado en memoria de la configuración LLM editable desde la pestaña Configuración.

- Un `LLMConfig` por proveedor (URL, modelo y API key). Cambiar de proveedor no borra la clave del
  anterior; todas desaparecen al reiniciar el servidor (no hay almacenamiento persistente de secretos,
  requisito del reto sobre credenciales: "sin almacenamiento persistente salvo que sea necesario").
- `public()` es lo único que sale hacia el navegador: nunca la clave, solo si está configurada y sus
  últimos 4 caracteres para reconocerla.
- Un `threading.Lock` protege el estado: lo leen los hilos de los trabajos y lo modifican las peticiones.
"""

from __future__ import annotations

import re
import threading
from typing import Any

from pydantic import SecretStr

from idor_ir.agents.providers import PROVIDERS, LLMConfig, validate_api_key, validate_base_url
from idor_ir.config import Settings
from idor_ir.redaction import mask_secret

MODEL_RE = re.compile(r"^[\w.:/@+\-]{1,120}$")  # incluye 'qwen3:4b-...' y 'proveedor/modelo:variante'


class LLMRuntime:
    def __init__(self, settings: Settings) -> None:
        self._lock = threading.Lock()
        self._configs: dict[str, LLMConfig] = {
            pid: LLMConfig(provider=pid, base_url=spec.base_url or spec.default_url) for pid, spec in PROVIDERS.items()
        }
        self._configs["ollama"] = LLMConfig(
            provider="ollama",
            base_url=str(settings.ollama_base_url).rstrip("/"),
            model=settings.ollama_model,
        )
        self._active = "ollama"
        # Conversación: proveedor y modelo propios (None / "" = los mismos de los agentes).
        self._chat_provider: str | None = settings.chat_provider if settings.chat_provider in PROVIDERS else None
        self._chat_model = (settings.chat_model or settings.ollama_chat_model).strip()
        if self._chat_model and not MODEL_RE.fullmatch(self._chat_model):
            self._chat_model = ""

    def get(self, provider: str) -> LLMConfig:
        with self._lock:
            if provider not in self._configs:
                raise KeyError(provider)
            return self._configs[provider].model_copy()

    def active(self) -> LLMConfig:
        with self._lock:
            return self._configs[self._active].model_copy()

    def chat_config(self) -> LLMConfig:
        """Configuración de la conversación: su proveedor (o el de los agentes) y su modelo (o el del proveedor)."""
        with self._lock:
            cfg = self._configs[self._chat_provider or self._active]
            return cfg.model_copy(update={"model": self._chat_model or cfg.model})

    def set_chat(self, provider: str | None, model: str | None) -> None:
        """Proveedor/modelo de la conversación. Valida antes de cambiar; la URL y la clave son las del proveedor."""
        provider = (provider or "").strip() or None
        model = (model or "").strip()
        if provider is not None and provider not in PROVIDERS:
            raise ValueError("Proveedor desconocido")
        if model and not MODEL_RE.fullmatch(model):
            raise ValueError("Nombre de modelo inválido")
        with self._lock:
            cfg = self._configs[provider or self._active]
            spec = PROVIDERS[cfg.provider]
            if provider is not None and spec.needs_key and cfg.api_key is None:
                raise ValueError(f"Configure primero la API key de {spec.label} (formulario de arriba)")
            if not (model or cfg.model):
                raise ValueError(f"Indique el modelo para la conversación ({spec.label} no tiene modelo configurado)")
            self._chat_provider, self._chat_model = provider, model

    def update(
        self,
        provider: str,
        *,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        clear_key: bool = False,
        activate: bool = False,
    ) -> None:
        """Valida TODO antes de modificar (una entrada inválida no deja el estado a medias)."""
        if provider not in PROVIDERS:
            raise ValueError("Proveedor desconocido")
        spec = PROVIDERS[provider]
        changes: dict[str, Any] = {}
        if base_url is not None:
            if spec.base_url is not None:
                raise ValueError(f"La URL de {spec.label} es fija")
            changes["base_url"] = validate_base_url(base_url)
        if model is not None:
            model = model.strip()
            if model and not MODEL_RE.fullmatch(model):
                raise ValueError("Nombre de modelo inválido")
            changes["model"] = model
        if clear_key:
            changes["api_key"] = None
        elif api_key:
            changes["api_key"] = SecretStr(validate_api_key(api_key))
        with self._lock:
            current = self._configs[provider]
            updated = current.model_copy(update=changes)
            if activate and not updated.model:
                raise ValueError("Seleccione un modelo antes de activar el proveedor")
            if activate and spec.needs_key and not updated.api_key:
                raise ValueError(f"Configure la API key de {spec.label} antes de activarlo")
            self._configs[provider] = updated
            if activate:
                self._active = provider

    def public(self) -> dict[str, Any]:
        with self._lock:
            providers = []
            for pid, spec in PROVIDERS.items():
                cfg = self._configs[pid]
                key = cfg.api_key.get_secret_value() if cfg.api_key else None
                providers.append(
                    {
                        "id": pid,
                        "label": spec.label,
                        "kind": spec.kind,
                        "cloud": spec.cloud,
                        "help": spec.help,
                        "needs_key": spec.needs_key,
                        "key_optional": not spec.needs_key and spec.kind != "ollama",
                        "key_configured": key is not None,
                        "key_hint": (mask_secret(key) if len(key) >= 16 else "••••") if key else None,
                        "base_url": cfg.base_url,
                        "base_url_editable": spec.base_url is None,
                        "model": cfg.model,
                        "off_lan": cfg.off_lan(),
                    }
                )
            chat_id = self._chat_provider or self._active
            chat_cfg = self._configs[chat_id]
            chat = {
                "provider": self._chat_provider,  # None = el mismo de los agentes
                "model": self._chat_model,  # "" = el modelo del proveedor
                "effective_provider": chat_id,
                "effective_label": PROVIDERS[chat_id].label,
                "effective_model": self._chat_model or chat_cfg.model,
                "off_lan": chat_cfg.off_lan(),
                "ready": bool(self._chat_model or chat_cfg.model)
                and (not PROVIDERS[chat_id].needs_key or chat_cfg.api_key is not None),
            }
            return {"active": self._active, "providers": providers, "chat": chat}
