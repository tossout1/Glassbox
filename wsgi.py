"""WSGI entry point for Gunicorn.

Run with one Gunicorn worker process because analysis job state is in memory.
"""
from main import app

__all__ = ["app"]
