import re
path = r'c:\Users\HELLO\Desktop\sih\04_FRONTEND\src\components\ProgressiveDisclosure\Level3TechnicalEvidence.tsx'
with open(path, 'r', encoding='utf-8') as f:
    c = f.read()
c = c.replace('<th>Blocklist</th>', '<th>Blocklist</th>\n                        <th>Actions</th>')

btn_html = '''                          <td>
                            <button 
                              className="btn-secondary" 
                              style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem', whiteSpace: 'nowrap' }}
                              onClick={() => {
                                setSandboxUrl(lnk.actualHref);
                                setSandboxLoading(true);
                              }}
                            >
                              View in Sandbox
                            </button>
                          </td>
                        </tr>'''
c = re.sub(r'</span>\n\s*</td>\n\s*</tr>', '</span>\n                          </td>\n' + btn_html, c)
with open(path, 'w', encoding='utf-8') as f:
    f.write(c)
