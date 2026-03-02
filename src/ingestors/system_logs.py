import win32evtlog
def read_windows_events(max_records=200):
  logs = []
  for log_type in ['Security','System','Application']:
    try:
      h = win32evtlog.OpenEventLog(None, log_type)
      flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
      events = win32evtlog.ReadEventLog(h, flags, 0)
      for e in (events or [])[:max_records]:
        logs.append({'source': log_type, 'event_id': e.EventID & 0xFFFF, 'category': e.EventCategory,
                     'time': e.TimeGenerated.Format(), 'computer': e.ComputerName})
      win32evtlog.CloseEventLog(h)
    except Exception:
      pass
  return logs
