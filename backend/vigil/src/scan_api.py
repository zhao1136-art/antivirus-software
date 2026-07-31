"""
Reusable scanner API used by both the CLI (scan.py) and the realtime
monitor (monitor.py / tray.py).

Loads PE + PS1 LightGBM boosters lazily and caches them, so a single
Scanner instance can process many files without re-loading the model.
Office and PDF pipelines are stateless rule scanners.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

import numpy as np
import lightgbm as lgb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from router import (  # noqa: E402
    detect_file_type, FILE_PE, FILE_PS1, FILE_OFFICE, FILE_PDF, FILE_UNKNOWN,
)
from features_ember import PEFeatureExtractor, feature_name  # noqa: E402
from extractor import extract as pe_rich_extract  # noqa: E402
from ps1_extractor import extract_path as ps1_extract, FEATURE_NAMES as PS1_FEATURE_NAMES  # noqa: E402
import office_scanner  # noqa: E402
import pdf_scanner  # noqa: E402
from virustotal import maybe_lookup_for_path  # noqa: E402


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PE_MODEL_PATH = os.path.join(HERE, "models", "model.lgbm")
PS1_MODEL_PATH = os.path.join(HERE, "models", "ps1_model.lgbm")

PE_THRESHOLD = 0.5
PS1_THRESHOLD = 0.5


@dataclass
class TopFeature:
    name: str
    value: float
    contrib: float


@dataclass
class ScanResult:
    """Pipeline-agnostic scan result."""
    path: str
    file_type: str                 # FILE_PE / FILE_PS1 / FILE_OFFICE / FILE_PDF / FILE_UNKNOWN
    verdict: str                   # "CLEAN" | "MALICIOUS" | "SKIPPED" | "ERROR"
    confidence: float              # 0..1 (post-threshold confidence in the verdict)
    raw_prob: float | None = None  # ML pipelines only: P(malicious)
    score: float | None = None     # rule pipelines only: total weighted score
    reasons: list[str] = field(default_factory=list)
    top_features: list[TopFeature] = field(default_factory=list)
    error: str | None = None
    vt_result: dict[str, Any] | None = None  # populated only when MALICIOUS + VIGIL_VT_API_KEY set

    def as_log_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["top_features"]:
            d.pop("top_features")
        if d.get("vt_result") is None:
            d.pop("vt_result", None)
        return d


class Scanner:
    """Caches PE + PS1 boosters; routes by file type."""

    def __init__(self,
                 pe_model_path: str = PE_MODEL_PATH,
                 ps1_model_path: str = PS1_MODEL_PATH):
        self.pe_model_path = pe_model_path
        self.ps1_model_path = ps1_model_path
        self._pe_booster: lgb.Booster | None = None
        self._pe_extractor: PEFeatureExtractor | None = None
        self._ps1_booster: lgb.Booster | None = None

    # ---- lazy loaders -----------------------------------------------------

    def _load_pe(self):
        if self._pe_booster is None:
            if not os.path.isfile(self.pe_model_path):
                raise FileNotFoundError(f"PE model not found: {self.pe_model_path}")
            self._pe_booster = lgb.Booster(model_file=self.pe_model_path)
            self._pe_extractor = PEFeatureExtractor()
        return self._pe_booster, self._pe_extractor

    def _load_ps1(self):
        if self._ps1_booster is None:
            if not os.path.isfile(self.ps1_model_path):
                raise FileNotFoundError(f"PS1 model not found: {self.ps1_model_path}")
            self._ps1_booster = lgb.Booster(model_file=self.ps1_model_path)
        return self._ps1_booster

    # ---- per-pipeline scans ----------------------------------------------

    def _scan_pe(self, path: str) -> ScanResult:
        try:
            booster, extractor = self._load_pe()
        except FileNotFoundError as e:
            return ScanResult(path=path, file_type=FILE_PE, verdict="ERROR",
                              confidence=0.0, error=str(e))
        with open(path, "rb") as f:
            bytez = f.read()
        x = extractor.feature_vector(bytez).reshape(1, -1)
        prob = float(booster.predict(x)[0])
        verdict = "MALICIOUS" if prob >= PE_THRESHOLD else "CLEAN"
        confidence = prob if verdict == "MALICIOUS" else (1.0 - prob)

        contribs = booster.predict(x, pred_contrib=True)[0][:-1]
        ranked = np.argsort(-contribs) if verdict == "MALICIOUS" else np.argsort(contribs)
        top = [TopFeature(name=feature_name(int(i)),
                          value=float(x[0, i]),
                          contrib=float(contribs[i])) for i in ranked[:5]]

        rich = pe_rich_extract(path)
        reasons = []
        if rich.is_pe:
            if rich.has_high_entropy_section:
                hi = [s.name for s in rich.sections if s.entropy >= 7.2]
                reasons.append(f"high-entropy section(s): {', '.join(hi)}")
            if rich.has_writable_executable_section:
                reasons.append("has writable+executable section (RWX)")
            if rich.no_imports:
                reasons.append("no imports at all (suspicious)")
            if rich.suspicious_count:
                reasons.append(f"{rich.suspicious_count} suspicious imports "
                               f"(e.g. {', '.join(rich.suspicious_imports[:3])})")
        else:
            reasons.append(f"not a valid PE: {rich.error}")

        return ScanResult(path=path, file_type=FILE_PE, verdict=verdict,
                          confidence=confidence, raw_prob=prob,
                          reasons=reasons, top_features=top)

    def _scan_ps1(self, path: str) -> ScanResult:
        try:
            booster = self._load_ps1()
        except FileNotFoundError as e:
            return ScanResult(path=path, file_type=FILE_PS1, verdict="ERROR",
                              confidence=0.0, error=str(e))
        feats = ps1_extract(path)
        x = np.asarray([feats.vector()], dtype=np.float32)
        prob = float(booster.predict(x)[0])
        verdict = "MALICIOUS" if prob >= PS1_THRESHOLD else "CLEAN"
        confidence = prob if verdict == "MALICIOUS" else (1.0 - prob)

        contribs = booster.predict(x, pred_contrib=True)[0][:-1]
        ranked = np.argsort(-contribs) if verdict == "MALICIOUS" else np.argsort(contribs)
        top = [TopFeature(name=PS1_FEATURE_NAMES[int(i)],
                          value=float(x[0, i]),
                          contrib=float(contribs[i])) for i in ranked[:5]]

        return ScanResult(path=path, file_type=FILE_PS1, verdict=verdict,
                          confidence=confidence, raw_prob=prob,
                          reasons=list(feats.reasons), top_features=top)

    def _scan_office(self, path: str) -> ScanResult:
        r = office_scanner.scan_file(path)
        return ScanResult(
            path=path, file_type=FILE_OFFICE, verdict=r.verdict,
            confidence=r.confidence / 100.0,
            score=r.score, reasons=list(r.reasons), error=r.error,
        )

    def _scan_pdf(self, path: str) -> ScanResult:
        r = pdf_scanner.scan_file(path)
        return ScanResult(
            path=path, file_type=FILE_PDF, verdict=r.verdict,
            confidence=r.confidence / 100.0,
            score=r.score, reasons=list(r.reasons), error=r.error,
        )

    # ---- public API -------------------------------------------------------

    def scan(self, path: str) -> ScanResult:
        if not os.path.isfile(path):
            return ScanResult(path=path, file_type=FILE_UNKNOWN,
                              verdict="ERROR", confidence=0.0,
                              error="file not found")
        try:
            kind = detect_file_type(path)
        except Exception as e:
            return ScanResult(path=path, file_type=FILE_UNKNOWN,
                              verdict="ERROR", confidence=0.0, error=str(e))

        if kind == FILE_PE:
            result = self._scan_pe(path)
        elif kind == FILE_PS1:
            result = self._scan_ps1(path)
        elif kind == FILE_OFFICE:
            result = self._scan_office(path)
        elif kind == FILE_PDF:
            result = self._scan_pdf(path)
        else:
            return ScanResult(path=path, file_type=FILE_UNKNOWN, verdict="SKIPPED",
                              confidence=1.0,
                              reasons=["unsupported file type"])

        if result.verdict == "MALICIOUS":
            result.vt_result = maybe_lookup_for_path(path)
        return result
