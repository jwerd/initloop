"""Bind controller Git queries to their explicitly selected project/worktree."""
import os

LOCATION_OVERRIDES = frozenset({
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
})


def project_environment():
    env = {key: value for key, value in os.environ.items() if key not in LOCATION_OVERRIDES}
    env['GIT_OPTIONAL_LOCKS'] = '0'
    return env
