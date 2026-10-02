import sqlite3, glob
files = glob.glob("*.db") + glob.glob("**/*.db", recursive=True)
if not files:
    print("no .db files found")
for f in files:
    con = sqlite3.connect(f)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    print(f, tables)
