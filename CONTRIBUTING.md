# Contribuir

1. Cree un entorno virtual con Python 3.12 o 3.13 e instale las dependencias de desarrollo:
   `pip install -e ".[dev]"` (ver [`docs/INSTALL.md`](docs/INSTALL.md)).
2. Antes de abrir un pull request, verifique que todo pasa:

   ```bash
   ruff check src tests && ruff format --check src tests
   mypy
   pytest
   ```

3. Las pruebas usan **solo datos sintéticos** generados en el propio test y servicios simulados (LLM, APIs de
   inteligencia de amenazas). No agregue logs reales, credenciales ni datos personales al repositorio.
4. Toda funcionalidad nueva debe venir con pruebas, tipado estricto (mypy) y, si cambia el comportamiento, con la
   actualización de la documentación en `docs/`.
5. Nuevas fuentes de inteligencia de amenazas: ver «Agregar una fuente» en [`docs/MCP.md`](docs/MCP.md).
