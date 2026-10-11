"""Fixtures de prueba.

IMPORTANTE: los datos de estos tests son SINTÉTICOS y mínimos. Solo usan los 8 campos
documentados en el reto [Reto §2] para probar la mecánica del código; NO representan el formato
real de `three_months.csv` (pendiente de validar, SPECS P1) ni ningún patrón de ataque real.
"""

from __future__ import annotations

from pathlib import Path

import pytest

HEADER = "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip"

ROWS = [
    "2020-01-01 10:00:00,200,example.test,/invoices/search?invoice_id=100&site_id=1&authtoken=SECRET_A,GET,-,ua-1,10.0.0.1",
    "2020-01-01 10:00:01,200,example.test,/invoices/search?invoice_id=101&site_id=1&authtoken=SECRET_A,GET,-,ua-1,10.0.0.1",
    "2020-01-01 10:00:02,403,example.test,/invoices/search?invoice_id=102&site_id=2&authtoken=SECRET_A,GET,-,ua-1,10.0.0.1",
    '2020-01-02 11:00:00,200,example.test,/home,GET,-,"ua, with comma",10.0.0.2',
    "no-es-fecha,abc,example.test,/invoices/search?invoice_id=XYZ&site_id=3&authtoken=SECRET_B,POST,-,ua-2,10.0.0.3",
]


@pytest.fixture
def sample_csv(tmp_path: Path) -> Path:
    path = tmp_path / "sample.csv"
    path.write_text(HEADER + "\n" + "\n".join(ROWS) + "\n", encoding="utf-8")
    return path
