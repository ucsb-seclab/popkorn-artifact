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

import config

NPROC = 8

def recreate_dir(d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=False)

def map_analyze_imports(driver_path):
    t = time.time()
    matching_imports = set()
    try:
        proj = angr.Project(driver_path)
        all_imports = {imp for obj in proj.loader.all_pe_objects for imp in obj.imports}

        matching_imports = all_imports.intersection({'ZwMapViewOfSection', "MmMapIoSpace", 'ZwOpenProcess'})
        # assert matching_imports, f"{driver_name} does not have any of the imports"
    except Exception as ex:
        print(ex)
        pass
    return driver_path, time.time() - t, matching_imports


def reduce_analyze_imports(driver_paths, results_generator):

    recreate_dir(OUT_DATASET_DIR)
    
    NON_IMPORTS = 0
    IMPORTS = 0
    for i, (driver_path, time_taken, matching_imports) in results_generator:
        driver_name = Path(driver_path).name
        assert driver_name

        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        if not matching_imports:
            NON_IMPORTS += 1
            continue

        IMPORTS += 1
        shutil.copyfile(driver_path, OUT_DATASET_DIR / driver_name)

    print(f"{NON_IMPORTS} of {len(driver_paths)} drivers did not have any sink functions available.")
    print(f"{IMPORTS} of {len(driver_paths)} drivers have been copied to the new dataset @ {OUT_DATASET_DIR}.")

def analyze_map_reduce(config_name, mapper, reducer):
    cur_config = config.CONFIGS[config_name]

    drivers = list(cur_config['driver_generator']())
    NON_IMPORTS = 0
    results = enumerate(pool.imap_unordered(mapper, drivers))
    reducer(drivers, results)


pool = Pool(NPROC)
DATASET_NAME = sys.argv[1]
DATASET_DIR = config.POPKORN_DIR / 'datasets'
OUT_DATASET_DIR = DATASET_DIR / (sys.argv[1] + '_imports_only')
analyze_map_reduce(sys.argv[1], map_analyze_imports, reduce_analyze_imports)
# analyze_map_reduce(sys.argv[1], map_angr_full_blown, reduce_angr_full_blown)
