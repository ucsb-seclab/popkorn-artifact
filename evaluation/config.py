import functools
from pathlib import Path
import glob
CUR_DIR = Path(__file__).absolute().parent
POPKORN_DIR = CUR_DIR.parent
DATASETS_DIR = POPKORN_DIR / 'datasets'


def dir_getter(dir_path: Path):
    yield from dir_path.glob('*.sys')

CONFIGS = {}
for f in DATASETS_DIR.iterdir():
    if not f.is_dir():
        continue
    name = f.name
    assert name
    CONFIGS[name] = {
        'driver_generator': functools.partial(dir_getter, f)
    }
