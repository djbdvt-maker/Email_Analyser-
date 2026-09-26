import re

path = r'c:\Users\HELLO\Desktop\sih\04_FRONTEND\src\components\Navbar.tsx'
with open(path, 'r', encoding='utf-8') as f:
    c = f.read()

c = c.replace('className=\\navbar\\>', 'className="navbar">')
c = c.replace('className=\\nav-brand\\', 'className="nav-brand"')
c = c.replace('className=\\brand-badge\\', 'className="brand-badge"')
c = c.replace('className=\\nav-actions\\', 'className="nav-actions"')
c = c.replace('className=\\user-profile\\', 'className="user-profile"')
c = c.replace('className=\\user-info\\', 'className="user-info"')
c = c.replace('className=\\user-name\\', 'className="user-name"')
c = c.replace('className=\\role-selector\\', 'className="role-selector"')
c = c.replace('className=\\user-role\\', 'className="user-role"')
c = c.replace('className=\\role-dropdown\\', 'className="role-dropdown"')
c = c.replace('className=\\role-option\\', 'className="role-option"')
c = c.replace('className=\\avatar\\', 'className="avatar"')

with open(path, 'w', encoding='utf-8') as f:
    f.write(c)
