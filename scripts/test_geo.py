import sqlite3
conn = sqlite3.connect(r'03_BACKEND\storage\hopzero.db')
c = conn.cursor()
c.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1")
inv_id = c.fetchone()[0]
c.execute("SELECT fact_type, payload FROM facts WHERE investigation_id=?", (inv_id,))
facts = c.fetchall()
has_geo = False
for f in facts:
    if f[0] == 'ip_geolocation':
        has_geo = True
        print('Geo Fact:', f)
print('Has Geo:', has_geo)
