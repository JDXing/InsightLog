InsightLog: A Lightweight Framework for Explainable Incident Detection in Linux System Logs

The system focuses on the analysis of Linux authentication and system logs (auth.log and syslog) generated on a single host or small-scale Linux environment.
It supports real-time log ingestion and detection as well as historical log replay for post-incident review and auditing.
The framework performs rule-based anomaly and incident detection using structured log fields and temporal correlation without relying on machine learning techniques.
Detected anomalies are aggregated into incident-level representations that include timelines, affected entities, severity levels, and supporting evidence.
An operator-centric decision-support interface provides explainable incident summaries and allows querying of detected incidents within specified time ranges.
The system operates under a human-in-the-loop model, where response actions are suggested but not automatically executed.