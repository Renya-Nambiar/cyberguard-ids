import os, shutil, sqlite3
def chrome_history_path():
  base = os.path.expanduser('~')
  return os.path.join(base, 'AppData','Local','Google','Chrome','User Data','Default','History')
def edge_history_path():
  base = os.path.expanduser('~')
  return os.path.join(base, 'AppData','Local','Microsoft','Edge','User Data','Default','History')
def read_history(db_path, limit=200):
  if not os.path.exists(db_path): return []
  temp = db_path + '.copy'
  try:
    shutil.copyfile(db_path, temp)
    conn = sqlite3.connect(temp); cur = conn.cursor()
    cur.execute('SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?', (limit,))
    rows = cur.fetchall(); conn.close(); os.remove(temp)
    return [{'url': r[0], 'title': r[1], 'visits': r[2], 'ts': r[3]} for r in rows]
  except Exception as e:
    return [{'error': str(e)}]
def read_browser_logs():
  return {'chrome': read_history(chrome_history_path(), 100),
          'edge': read_history(edge_history_path(), 100)}
