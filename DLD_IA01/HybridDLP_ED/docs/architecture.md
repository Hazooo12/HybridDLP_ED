# Hybrid-DLP-ED – Architecture (Final)

## Components
1. Sensor (Windows Service – SYSTEM)
   - File system monitoring
   - USB detection
   - Event generation only (no analysis)

2. IPC Queue
   - Redis local
   - Producer–Consumer model
   - Backpressure supported

3. Worker Process
   - Event consumption
   - Content analysis (later)
   - Risk scoring trigger

4. Decision Engine
   - Log / Alert / Block

5. Central Server
   - Policy distribution
   - Monitoring dashboard

## Design Principles
- Event-driven
- Asynchronous
- Resource-aware
- Resilient (self-healing)

