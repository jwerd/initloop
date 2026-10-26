"""Dependency-free packaging checks for a portable, model-free skill."""
from pathlib import Path
import re
import sys

root=Path(sys.argv[1])
entry=(root/'SKILL.md').read_text()
assert entry.startswith('---\n')
header,body=entry[4:].split('\n---\n',1)
fields=dict(line.split(':',1) for line in header.splitlines())
assert fields['name'].strip()==root.name
assert len(fields['description'].strip())>20
assert re.fullmatch('[a-z0-9-]{1,64}',fields['name'].strip())
for relative in re.findall(r'\]\((references/[^)]+)\)',body):
    assert (root/relative).is_file(),relative
for source in root.rglob('*.py'):
    compile(source.read_text(),str(source),'exec')
    assert not re.search(r'\b(import openai|from openai|import anthropic|google\.genai)\b',source.read_text()),source
print('PASS: frontmatter, referenced resources, Python syntax, no model SDK imports')
