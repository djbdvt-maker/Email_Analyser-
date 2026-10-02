import sqlite3

conn = sqlite3.connect(r'03_BACKEND\storage\hopzero.db')
c = conn.cursor()

c.execute("SELECT id, title, created_at FROM investigations ORDER BY created_at DESC LIMIT 1")
inv = c.fetchone()
print('Investigation:', inv)

c.execute("SELECT fact_type, payload FROM facts WHERE investigation_id=?", (inv[0],))
facts = c.fetchall()
for f in facts:
    if f[0] == 'ip_geolocation' or 'geo' in f[0]:
        print('Geo Fact:', f)
