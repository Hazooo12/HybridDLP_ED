from event_schema import normalize_event

raw = {
    "type": "file_created",
    "source": "file_sensor",
    "object": {"path": "C:\\test\\a.txt", "size": 123, "ext": ".txt"},
    "context": {"fg_app": "notepad.exe", "window_title": "a.txt - Notepad"},
}

e = normalize_event(raw)
print(e)