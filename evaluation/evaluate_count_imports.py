import argparse
from collections import Counter, defaultdict
import functools
from lib2to3.pgen2 import driver
import os
import shutil
import subprocess
import angr
import archinfo
import cle
import sys
import time

from multiprocessing.pool import Pool
from pathlib import Path
from util import fully_normalized_drivername

import config

def map_analyze_imports(driver_path):
    t = time.time()
    matching_imports = set()
    try:
        proj = angr.Project(driver_path)
        all_imports = {imp for obj in proj.loader.all_pe_objects for imp in obj.imports}

        matching_imports = all_imports.intersection({'ZwMapViewOfSection', 'MmMapIoSpace', 'ZwOpenProcess'})
        # assert matching_imports, f"{driver_name} does not have any of the imports"
    except Exception as ex:
        print(ex)
        pass
    return driver_path, time.time() - t, matching_imports


def reduce_analyze_imports(driver_paths, results_generator):
    IMPORTS_BY_DRIVER = defaultdict(set)
    
    for _, (driver_path, _, matching_imports) in results_generator:
        d_name = driver_path.name
        if ARGS.deduplicate:
            d_name = fully_normalized_drivername(d_name)
        IMPORTS_BY_DRIVER[d_name].update(matching_imports)

    COUNTS_FOR_IMPORT = Counter()
    for driver, imps in IMPORTS_BY_DRIVER.items():
        COUNTS_FOR_IMPORT.update(imps)
    print(COUNTS_FOR_IMPORT)
    print(len(IMPORTS_BY_DRIVER))

def analyze_map_reduce(config_name, mapper, reducer):
    cur_config = config.CONFIGS[config_name]

    drivers = list(cur_config['driver_generator']())
    NON_IMPORTS = 0
    results = enumerate(pool.imap_unordered(mapper, drivers))
    reducer(drivers, results)

AVAILABLE_CPUS = len(os.sched_getaffinity(0))
NPROC = AVAILABLE_CPUS >> 1

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--parallel', default=NPROC, type=int, help='the number of processes to run in parallel')
parser.add_argument('-d', '--deduplicate', default=False, action='store_true')
parser.add_argument('dataset_name', choices=list(sorted(config.CONFIGS.keys())))
ARGS = parser.parse_args()

pool = Pool(ARGS.parallel)

DATASET_NAME = ARGS.dataset_name
analyze_map_reduce(DATASET_NAME, map_analyze_imports, reduce_analyze_imports)
# analyze_map_reduce(sys.argv[1], map_angr_full_blown, reduce_angr_full_blown)
