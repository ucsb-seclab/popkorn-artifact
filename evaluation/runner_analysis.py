import functools
import json
from lib2to3.pgen2 import driver
import os
import shutil
import subprocess
import tempfile
import angr
import sys
import time

from multiprocessing.pool import Pool
from pathlib import Path

import config

def recreate_dir(d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=False)

def get_next_free_path(id):
    for i in range(100000000):
        p = id + f'_run{i}'
        if not os.path.exists(p):
            return p
    assert False


def map_analyze_imports(out_dir_path, driver_path):
    t = time.time()
    proj = angr.Project(driver_path)
    all_imports = {imp for obj in proj.loader.all_pe_objects for imp in obj.imports}

    matching_imports = all_imports.intersection({'ZwMapViewOfSection', "MmMapIoSpace", 'ZwOpenProcess'})
    # assert matching_imports, f"{driver_name} does not have any of the imports"

    return driver_path, time.time() - t, matching_imports


def reduce_analyze_imports(out_dir_path, driver_paths, results_generator):
    NON_IMPORTS = 0
    for i, (driver_name, time_taken, matching_imports) in results_generator:
        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        if not matching_imports:
            NON_IMPORTS += 1
            print('$' * 40)
            print('$' * 40)
            print('$' * 40)
            print(driver_name)
            print('$' * 40)
            print('$' * 40)
            print('$' * 40)

    print(f"{NON_IMPORTS} of {len(driver_paths)} drivers did not have any sink functions available.")

def is_vulnerable_result(subprocess_result: subprocess.CompletedProcess):
    if b'Boom!' in subprocess_result.stdout:
        assert subprocess_result.returncode == 0, f'process died {repr(subprocess_result)}'
        return True
    return False

def map_angr_full_blown(out_dir_path, driver_path):
    t = time.time()

    driver_name = os.path.basename(driver_path)
    result_dir = out_dir_path / driver_name
    recreate_dir(result_dir)

    cmd = f'timeout {ARGS.timeout} python'.split()
    cmd += [config.POPKORN_DIR / 'angr_analysis/angr_full_blown.py']
    if ARGS.directed:
        cmd += ['--directed']
    cmd += [driver_path]
    result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    if result.stdout:
        with open(str(result_dir / 'stdout'), 'wb') as f:
            f.write(result.stdout)
    if result.stderr:
        with open(str(result_dir / 'stderr'), 'wb') as f:
            f.write(result.stderr)

    if is_vulnerable_result(result):
        with open(str(result_dir / 'vulnerable'), 'wb') as f:
            f.write(result.stdout)

    with open(str(result_dir / 'status'), 'wb') as f:
        f.write(str(result.returncode).encode())

    return driver_path, time.time() - t, result

def reduce_angr_full_blown(out_dir_path: Path, driver_paths, results_generator):
    results = {}

    for i, (driver_path, time_taken, result) in results_generator:
        driver_path: str
        time_taken: float
        result: subprocess.CompletedProcess
        
        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        x = {
            'status': result.returncode,
            'time_taken': time_taken,
            'vulnerable': is_vulnerable_result(result)
        }
        results[os.path.basename(driver_path)] = x

    with open(out_dir_path / 'complete.json', 'w') as f:
        json.dump(results, f, indent=2)

def analyze_map_reduce(config_name, mapper, reducer):
    cur_config = config.CONFIGS[config_name]

    OUTDIR = f'results_{config_name}_timeout{ARGS.timeout}'
    if ARGS.directed:
        OUTDIR += '_directed'
    OUTDIR = config.CUR_DIR / OUTDIR

    with tempfile.TemporaryDirectory(dir='.', prefix=f'{OUTDIR}_') as TMP_OUT_DIR:
        TMP_OUT_DIR = Path(TMP_OUT_DIR)
        print(f"Writing results of analyzing {config_name=} to {TMP_OUT_DIR=}")

        drivers = list(cur_config['driver_generator']())
        NON_IMPORTS = 0
        results = enumerate(pool.imap_unordered(functools.partial(mapper, TMP_OUT_DIR), drivers))
        reducer(TMP_OUT_DIR, drivers, results)

        REAL_OUT_DIR = Path(get_next_free_path(str(OUTDIR)))
        print(f"Moving results from {TMP_OUT_DIR} to {REAL_OUT_DIR}")
        shutil.rmtree(REAL_OUT_DIR, ignore_errors=True)
        os.makedirs(REAL_OUT_DIR)
        shutil.copytree(TMP_OUT_DIR, REAL_OUT_DIR, dirs_exist_ok=True)



ANALYSES = {
    'imports': {
        'map': map_analyze_imports,
        'reduce': reduce_analyze_imports,
    },
    'full_blown': {
        'map': map_angr_full_blown,
        'reduce': reduce_angr_full_blown
    }
}

SECONDS = 1
MINUTES = 60 * SECONDS
HOURS = 60 * MINUTES
DAYS = 24 * HOURS

DEFAULT_TIMEOUT = 10 * MINUTES


AVAILABLE_CPUS = len(os.sched_getaffinity(0))
NPROC = AVAILABLE_CPUS >> 1

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directed', default=False, action='store_true', help='use directed angr analysis')
    parser.add_argument('-t', '--timeout', default=DEFAULT_TIMEOUT, type=int, help='the timeout for each analysis')
    parser.add_argument('-p', '--parallel', default=(AVAILABLE_CPUS//2), type=int, help='the number of tasks to spawn in parallel')
    parser.add_argument('-a', '--analysis', default='full_blown', choices=list(ANALYSES.keys()), help='which analysis to run')
    parser.add_argument('dataset', choices=list(config.CONFIGS.keys()))

    ARGS = parser.parse_args()

    pool = Pool(ARGS.parallel)

    analysis = ANALYSES[ARGS.analysis]
    analyze_map_reduce(ARGS.dataset, analysis['map'], analysis['reduce'])
