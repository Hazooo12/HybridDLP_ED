"""
Agent — camada L1 + L2 do Hybrid DLP (endpoint).

- **L1**: sensores (file, clipboard, USB, rede, …), captura de eventos, fila em memória.
- **L2**: pipeline de eventos (`event_pipeline`), sinks JSONL/SQLite, correlator opcional,
  fila persistente para o Worker em `agent.persistent_queue`.

O processo de **deteção pesada** (YARA, OCR, ML, risk) está em `worker/` (L3), processo separado.
"""

__all__: list[str] = []
