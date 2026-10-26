"""Bounded OpenAPI/Swagger metadata; no examples, reference resolution or YAML execution.

JSON is decoded strictly. YAML support is intentionally only conventional
(two-space) block mappings for version, paths and operation keys. Other fields
are ignored, never represented as a complete parsed OpenAPI document.
"""
from bisect import bisect_right
import json
from pathlib import PurePosixPath
import re
from urllib.parse import unquote

from .core import secret_like

_MAX_BYTES = 1024 * 1024
_MAX_NODES = 20000
_MAX_DEPTH = 64
_METHODS = {'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'}
_CONVENTIONAL = {'openapi.json', 'openapi.yaml', 'openapi.yml',
                 'swagger.json', 'swagger.yaml', 'swagger.yml'}
_STATIC = 'Static metadata only; operation behavior and provider fidelity are unverified.'
_YAML = 'Conventional two-space block-mapping YAML subset; schemas and free-form values are not interpreted.'
_REFS = 'References are not resolved; referenced content and operation completeness remain unverified.'


class _Unsupported(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Unsupported('Duplicate mapping key.')
        result[key] = value
    return result


class _JSONPositions:
    """Index key positions after standard-library JSON validation, without snippets."""
    def __init__(self, text):
        self.text = text
        self.decoder = json.JSONDecoder()
        self.newlines = [match.start() for match in re.finditer(r'\r\n|\r|\n', text)]
        self.positions = {}
        self.nodes = 0

    def whitespace(self, position):
        while position < len(self.text) and self.text[position].isspace():
            position += 1
        return position

    def scan(self, position=0, path=(), depth=0):
        self.nodes += 1
        if self.nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise _Unsupported('Contract structure exceeds discovery budget.')
        position = self.whitespace(position)
        char = self.text[position]
        if char == '{':
            position = self.whitespace(position + 1)
            if self.text[position] == '}':
                return position + 1
            while True:
                key_position = position
                key, position = self.decoder.raw_decode(self.text, position)
                if not path or (path[0] == 'paths' and len(path) <= 2):
                    self.positions[path + (key,)] = bisect_right(self.newlines, key_position) + 1
                position = self.whitespace(position)
                position = self.scan(position + 1, path + (key,), depth + 1)
                position = self.whitespace(position)
                if self.text[position] == '}':
                    return position + 1
                position = self.whitespace(position + 1)
        if char == '[':
            position = self.whitespace(position + 1)
            if self.text[position] == ']':
                return position + 1
            index = 0
            while True:
                position = self.scan(position, path + (index,), depth + 1)
                index += 1
                position = self.whitespace(position)
                if self.text[position] == ']':
                    return position + 1
                position = self.whitespace(position + 1)
        return self.decoder.raw_decode(self.text, position)[1]


def _version(name, value):
    if not isinstance(value, str):
        return None
    pattern = r'3\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]{1,30})?' if name == 'openapi' else r'2\.0'
    return value if len(value) <= 64 and re.fullmatch(pattern, value) else None


def _route(value):
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 300:
        return False
    if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%{}/-]*", value):
        return False
    without_parameters = re.sub(r'\{[A-Za-z_][A-Za-z0-9_]*\}', '', value)
    return not re.search(r'[{}]', without_parameters) and not secret_like(unquote(value))


def _has_refs(value):
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if '$ref' in node:
                return True
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return False


def _report(source, name, version=None, line=1, status='unsupported', limitations=None, operations=None):
    return {'source': source, 'name': name, 'version': version, 'line': line,
            'operations': operations or [], 'status': status,
            'limitations': list(dict.fromkeys([_STATIC, *(limitations or [])]))}


def _json_contract(text, source, hint):
    name = hint
    try:
        document = json.loads(text, object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(_Unsupported('Nonstandard JSON constant.')))
        if not isinstance(document, dict):
            return _report(source, hint, limitations=['Contract root must be a mapping.']) if hint else None
        name = 'openapi' if 'openapi' in document else 'swagger' if 'swagger' in document else hint
        if not name:
            return None
        if 'openapi' in document and 'swagger' in document:
            raise _Unsupported('Conflicting contract version declarations.')
        index = _JSONPositions(text)
        index.scan()
        version = _version(name, document.get(name))
        line = index.positions.get((name,), 1)
        if version is None:
            return _report(source, name, line=line, limitations=['Unsupported or missing contract version.'])
        paths = document.get('paths')
        if not isinstance(paths, dict):
            return _report(source, name, version, line, 'partial', ['No supported paths mapping present.'])
        limitations = []
        operations = []
        for path, item in paths.items():
            if not _route(path):
                limitations.append('Unsupported or unsafe route path omitted.')
                continue
            if not isinstance(item, dict):
                limitations.append('Unsupported path-item structure omitted.')
                continue
            for method, value in item.items():
                if method not in _METHODS:
                    continue
                if not isinstance(value, dict):
                    limitations.append('Unsupported operation mapping omitted.')
                    continue
                operations.append({'method': method.upper(), 'path': path, 'source': source,
                                   'line': index.positions[('paths', path, method)]})
        if _has_refs(document):
            limitations.append(_REFS)
        return _report(source, name, version, line, 'partial' if limitations else 'static', limitations, operations)
    except _Unsupported as error:
        return _report(source, name, limitations=[str(error)]) if name else None
    except (ValueError, RecursionError, IndexError):
        return _report(source, hint or 'openapi', limitations=['Malformed or excessive JSON structure.']) if hint else None


def _mapping(line):
    """Split one supported YAML mapping key, respecting quoted text/comments."""
    quote = None
    position = 0
    while position < len(line):
        char = line[position]
        if quote == '"' and char == '\\':
            position += 2
            continue
        if quote:
            if char == quote:
                if quote == "'" and position + 1 < len(line) and line[position + 1] == "'":
                    position += 2
                    continue
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == '#':
            return None
        elif char == ':' and (position + 1 == len(line) or line[position + 1].isspace()):
            return line[:position].strip(), line[position + 1:].strip()
        position += 1
    return None


def _scalar(text):
    if text.startswith('"'):
        try:
            value, end = json.JSONDecoder().raw_decode(text)
            return value if not text[end:].strip() or text[end:].lstrip().startswith('#') else None
        except ValueError:
            return None
    if text.startswith("'"):
        match = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", text)
        return match.group(1).replace("''", "'") if match else None
    return text.split(' #', 1)[0].rstrip()


def _yaml_contract(text, source, hint):
    name = hint
    version = None
    version_line = 1
    limitations = [_YAML]
    operations = []
    root_keys = set()
    paths = set()
    methods = set()
    in_paths = False
    current_path = None
    block_indent = None
    content_seen = False
    document_ended = False
    path_mapping_seen = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        if '\t' in raw[:len(raw) - len(raw.lstrip())]:
            return _report(source, name or 'openapi', version, version_line, limitations=['YAML tab indentation is unsupported.'])
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if document_ended:
            return _report(source, name or 'openapi', version, version_line, limitations=['Content after YAML document end is unsupported.'])
        indent = len(raw) - len(raw.lstrip(' '))
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        if stripped == '---':
            if content_seen:
                return _report(source, name or 'openapi', version, version_line, limitations=['Multiple YAML documents are unsupported.'])
            continue
        if stripped == '...':
            document_ended = True
            in_paths = False
            continue
        content_seen = True
        # Every substantive route-level line ends the preceding path item,
        # including malformed keys and unsupported one/three-space indentation.
        # A later method must not inherit a route across unknown structure.
        if in_paths and (indent < 4 or indent == 5):
            current_path = None
        pair = _mapping(stripped)
        if not pair:
            if in_paths and indent <= 4:
                current_path = None
                limitations.append('Unsupported YAML path or operation structure omitted.')
            continue
        key_raw, value_raw = pair
        key = _scalar(key_raw)
        if not isinstance(key, str):
            if in_paths and indent <= 4:
                current_path = None
            limitations.append('Unsupported YAML key omitted.')
            continue
        if value_raw.startswith(('!', '&', '*')) or key == '<<':
            return _report(source, name or 'openapi', version, version_line, limitations=['YAML tags, anchors, aliases and merge keys are unsupported.'])
        if key == '$ref':
            limitations.append(_REFS)
        if value_raw.startswith(('|', '>')):
            block_indent = indent
        if indent == 0:
            if key in root_keys:
                return _report(source, name or 'openapi', version, version_line, limitations=['Duplicate mapping key.'])
            root_keys.add(key)
            in_paths = key == 'paths'
            current_path = None
            if key in {'openapi', 'swagger'}:
                if name and name != key and name in root_keys:
                    return _report(source, name, limitations=['Conflicting contract version declarations.'])
                name, version, version_line = key, _version(key, _scalar(value_raw)), lineno
            if in_paths:
                if value_raw not in ('', '{}') and not value_raw.startswith('#'):
                    return _report(source, name or 'openapi', version, version_line, limitations=['Flow-style or referenced YAML paths are unsupported.'])
                path_mapping_seen = True
        elif in_paths and indent == 2:
            if key in paths:
                return _report(source, name or 'openapi', version, version_line, limitations=['Duplicate path mapping key.'])
            paths.add(key)
            current_path = key if _route(key) and (not value_raw or value_raw.startswith('#')) else None
            if current_path is None and not key.startswith('x-'):
                limitations.append('Unsupported path-item structure or unsafe path omitted.')
        elif in_paths and indent == 4 and current_path and key in _METHODS:
            identity = (current_path, key)
            if identity in methods:
                return _report(source, name or 'openapi', version, version_line, limitations=['Duplicate operation mapping key.'])
            methods.add(identity)
            if value_raw not in ('', '{}') and not value_raw.startswith('#'):
                limitations.append('Unsupported operation mapping omitted.')
                continue
            operations.append({'method': key.upper(), 'path': current_path, 'source': source, 'line': lineno})
        elif in_paths and indent < 6:
            if key.startswith(('/', '?')):
                current_path = None
            limitations.append('Unsupported YAML indentation or path metadata omitted.')
    if not name:
        return None
    if version is None:
        return _report(source, name, line=version_line, limitations=['Unsupported or missing contract version.', _YAML])
    if not path_mapping_seen:
        limitations.append('No supported paths mapping present.')
    return _report(source, name, version, version_line, 'partial', limitations, operations)


def discover_contract(text, source):
    """Return bounded structural metadata, or None for unrelated input.

    No file reads, imports of project code, YAML evaluation, reference expansion
    or network access occur. Limitations are fixed messages, never source values.
    """
    filename = PurePosixPath(source).name.lower()
    hint = ('swagger' if filename.startswith('swagger.') else 'openapi') if filename in _CONVENTIONAL else None
    if not isinstance(text, str):
        return _report(source, hint, limitations=['Contract input must be text.']) if hint else None
    if len(text) > _MAX_BYTES or len(text.encode('utf-8', errors='replace')) > _MAX_BYTES or text.count('\n') > _MAX_NODES:
        return _report(source, hint or 'openapi', limitations=['Contract exceeds discovery byte or line budget.']) if hint else None
    if '\x00' in text:
        return _report(source, hint, limitations=['NUL-containing contract input is unsupported.']) if hint else None
    if text.lstrip().startswith(('{', '[')) or filename.endswith('.json'):
        return _json_contract(text, source, hint)
    if hint is None:
        for raw in text.splitlines():
            if raw and not raw[0].isspace():
                pair = _mapping(raw)
                if pair and _scalar(pair[0]) in {'openapi', 'swagger'}:
                    hint = _scalar(pair[0])
                    break
        if hint is None:
            return None
    return _yaml_contract(text, source, hint)
