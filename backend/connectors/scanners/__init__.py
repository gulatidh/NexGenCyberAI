"""GitHub-Actions-driven scanners (SAST / Network / Dependency).

Each scanner here is a thin BaseConnector subclass that delegates the
heavy lifting to a GitHub Actions workflow (same pattern as WebConnector
for ZAP). Results are POSTed back to /api/v1/scans/ingest/.
"""
