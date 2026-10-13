# Política de seguridad

## Reportar una vulnerabilidad

Si encuentra una vulnerabilidad, **no abra un issue público**. Repórtela de forma privada con
[GitHub Security Advisories](../../security/advisories/new) («Report a vulnerability»), indicando:

- versión o commit afectado;
- pasos para reproducirla y el impacto esperado;
- si la conoce, una posible mitigación.

Se confirmará la recepción y se acordará con usted la publicación de la corrección.

## Alcance y modelo de amenazas

IR Platform es una herramienta de análisis **para uso local o en una red de confianza**:

- La interfaz web escucha solo en `127.0.0.1` por defecto. Fuera de ella **no arranca** sin `IRP_ACCESS_TOKEN`
  (≥ 16 caracteres; fail-closed); para exponerla use además TLS (`--ssl-certfile/--ssl-keyfile` o un proxy de
  `IRP_TRUSTED_PROXIES`) y separe funciones con `IRP_APPROVER_TOKEN` (rol aprobador).
- Las URLs que la interfaz permite configurar (LLM, MISP) solo pueden apuntar a hosts de la lista blanca del
  administrador (`IRP_LLM_ALLOWED_HOSTS`, `TI_ALLOWED_HOSTS`); cada conexión se verifica y se fija a la IP comprobada.
- Los logs analizados contienen credenciales y datos personales de terceros: `data/` y `output/` nunca deben
  publicarse. `output/<run>/sensitive/` (solo el dueño, 0700/0600) contiene los tokens completos;
  `work/parsed.parquet` guarda solo su huella.
- Las claves de API (LLM e inteligencia de amenazas) se ingresan por la interfaz y viven solo en memoria.
- Las acciones de contención se generan en modo *dry-run*: la plataforma no modifica sistemas externos.

Los controles implementados (OWASP Cheat Sheet Series) están en [`docs/SPECS.md`](docs/SPECS.md#9-controles-de-seguridad).
