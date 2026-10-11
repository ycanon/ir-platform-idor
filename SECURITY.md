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

- La interfaz web escucha solo en `127.0.0.1` por defecto. Exponerla a una red requiere `IRP_ACCESS_TOKEN` y un
  proxy inverso con TLS.
- Los logs analizados contienen credenciales y datos personales de terceros: `data/` y `output/` nunca deben
  publicarse. `output/<run>/sensitive/` y `work/parsed.parquet` contienen tokens completos.
- Las claves de API (LLM e inteligencia de amenazas) se ingresan por la interfaz y viven solo en memoria.
- Las acciones de contención se generan en modo *dry-run*: la plataforma no modifica sistemas externos.

Los controles implementados (OWASP Cheat Sheet Series) están en [`docs/SPECS.md`](docs/SPECS.md#9-controles-de-seguridad).
