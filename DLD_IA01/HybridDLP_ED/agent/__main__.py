"""
Ponto de entrada: `python -m agent` — mesmo que `python -m agent.sensor` (Sensor L1/L2).

Não existe pacote paralelo `sensor_service`; o núcleo é este pacote `agent`.
"""
from __future__ import annotations


def main() -> None:
    from agent.sensor import main as sensor_main

    sensor_main()


if __name__ == "__main__":
    main()
