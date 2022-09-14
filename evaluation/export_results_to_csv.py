from collections import defaultdict
import glob
import os
import sys
import csv
import angr
from pathlib import Path
from util import fully_normalized_drivername

MSG_NO_IMPORTS_FOUND = b'''Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..

ZwOpenProcess import not found!

MmMapIoSpace import not found!

ZwMapViewOfSection import not found!
'''
MSG_NO_DRIVERENTRY = b'Could not find a successful DriverEntry run!!!'


GLOB = sys.argv[1]

per_driver_results = defaultdict(dict)

driver_names = set()
analyses = set()

columns = ['Driver']
for analysis_run_complete in glob.iglob(os.path.join(GLOB, 'complete.json')):
    analysis_run_directory = Path(analysis_run_complete).absolute().resolve().parent
    ANALYSIS_ID = analysis_run_directory.name
    ANALYSIS_ID = ANALYSIS_ID.split('results_')[1]
    ANALYSIS_ID = ''.join(ANALYSIS_ID.split('_imports_only'))
    analyses.add(ANALYSIS_ID)

    for driver_results_dir in analysis_run_directory.glob('*.sys'):
        assert driver_results_dir.is_dir(), f"{driver_results_dir=} is not a directory"
        DRIVER_NAME = driver_results_dir.name
        driver_names.add(DRIVER_NAME)

        flagged = (driver_results_dir / 'vulnerable').is_file()
        with open(driver_results_dir / 'status', 'r') as f:
            status = f.read()
        if os.path.exists(driver_results_dir / 'stdout'):
            with open(driver_results_dir / 'stdout', 'rb') as f:
                stdout = f.read()
        else:
            stdout = b''
        timed_out = status.strip() == '124'

        msg = ''
        if flagged:
            msg = 'VULNERABLE'
        elif status.strip() == '124': # timeout
            msg = 'timeout'
        elif driver_results_dir.name.startswith("CITMDRV_IA64_"):
            msg = 'unsupported architecture: ia64'
        elif MSG_NO_IMPORTS_FOUND in stdout:
            msg = 'no sinks found'
        # elif MSG_NO_DRIVERENTRY in stdout:
        #     msg = 'could not locate ioctl handler'
        per_driver_results[DRIVER_NAME][ANALYSIS_ID] = {
            'driver': driver_results_dir.name,
            'analysis': msg
        }

fieldnames = ['driver_name', 'normalized_driver_name']

ANALYSIS_KEYS = list(sorted(analyses))
DRIVER_KEYS = list(sorted(driver_names))
fieldnames += ANALYSIS_KEYS

with open('results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    for driver_name in DRIVER_KEYS:
        norm = fully_normalized_drivername(driver_name)
        driver_results = per_driver_results[driver_name]
        writer.writerow([driver_name.replace(',', '_'), norm] + [driver_results[anal]['analysis'] for anal in ANALYSIS_KEYS])
        
