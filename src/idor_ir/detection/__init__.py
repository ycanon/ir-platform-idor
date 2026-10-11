"""Detección de ataques. MVP: IDOR. Extensible mediante `detection.base.register`."""

from idor_ir.detection.base import DetectionResult, Detector, register, registered
from idor_ir.detection.idor import IdorDetector
from idor_ir.detection.metrics import traffic_metrics

__all__ = ["DetectionResult", "Detector", "IdorDetector", "register", "registered", "traffic_metrics"]
