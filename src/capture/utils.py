import socket, psutil
def pick_interface(name_hint='auto'):
  if name_hint != 'auto': return name_hint
  for iface, addrs in psutil.net_if_addrs().items():
    for addr in addrs:
      if addr.family == socket.AF_INET: return iface
  return None
