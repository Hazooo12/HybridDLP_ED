"""
Sinks module - Event output handlers
"""
from sinks.file_sink import JsonlFileSink
from sinks.sqlite_sink import SQLiteEventStore

__all__ = ['JsonlFileSink', 'SQLiteEventStore']
