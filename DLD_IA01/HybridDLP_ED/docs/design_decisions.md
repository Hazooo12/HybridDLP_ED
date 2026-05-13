\- Windows Service is used instead of user-mode application to ensure continuous monitoring with SYSTEM privilege.

\- Event-driven architecture is chosen to prevent blocking and reduce resource usage on SME workstations.

\- Sensor and Worker are separated to isolate heavy analysis from monitoring logic.

\- A local IPC queue is used to handle event bursts safely.



