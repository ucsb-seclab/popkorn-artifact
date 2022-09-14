import argparse
from collections import defaultdict
import glob
from io import SEEK_SET
import json
import os
import re
import sys
import csv
import tempfile
import angr
from pathlib import Path

from util import extract_drivername, fully_normalized_drivername

MSG_NO_IMPORTS_FOUND = b'''Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..

ZwOpenProcess import not found!

MmMapIoSpace import not found!

ZwMapViewOfSection import not found!
'''
MSG_NO_DRIVERENTRY = b'Could not find a successful DriverEntry run!!!'

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--deduplicate', help='whether to use deduplicated names or not', default=False, action='store_true')
parser.add_argument('results_glob')
ARGS = parser.parse_args()

GLOB = ARGS.results_glob
DO_DEDUPLICATE = ARGS.deduplicate

per_driver_results = defaultdict(set)

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

        if not (driver_results_dir / 'vulnerable').is_file():
            continue
        with open(driver_results_dir / 'status', 'r') as f:
            status = f.read()
        with open(driver_results_dir / 'vulnerable', 'r') as f:
            vuln_desc = f.read()

        with open(driver_results_dir / 'time_taken', 'r') as f:
            time_taken = float(f.read())

        assert 'Boom!' in vuln_desc
        lines = [l.strip() for l in vuln_desc.strip().split('\n') if l.strip()]

        cur_results = set()
        cur_boom = -1

        # if 'NTIOLib' in DRIVER_NAME:
        #     import ipdb; ipdb.set_trace()
        while (cur_boom := vuln_desc.find('[+] Boom! Here is the IOCTL: ', cur_boom+1)) != -1:
            lines_after = vuln_desc[cur_boom:].split('\n')
            # print(cur_boom, lines_after[:3])
            ioctl_code = int(lines_after[0].split()[-1], base=0)

            ioctl_func_match = re.search('IOCTL for (MmapIoSpace|ZwOpenProcess|ZwMapViewOfSection):  (0x[0-9a-f]+)', lines_after[1])
            assert ioctl_func_match, f'Unknown_pattern for {lines_after[:5]}'
            func, ioctl_code_2 = ioctl_func_match.groups()
            ioctl_code_2 = int(ioctl_code_2, base=0)
            assert ioctl_code == ioctl_code_2
            d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
            cur_results.add((d_name, func, time_taken))

        d_name = (extract_drivername if not DO_DEDUPLICATE else fully_normalized_drivername)(DRIVER_NAME)
        per_driver_results[d_name].update(cur_results)

# import ipdb; ipdb.set_trace()
fieldnames = ['driver_name', 'triggered_sink_function', 'time_taken']

DRIVER_KEYS = list(sorted(per_driver_results.keys()))

per_driver_dedup = {}
with tempfile.TemporaryFile('w+', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    for driver_name in DRIVER_KEYS:
        driver_results = per_driver_results[driver_name]
        for full_name, func, time_taken in sorted(driver_results, key=lambda x: x[1]): # sort by func
            writer.writerow([driver_name, func, time_taken])

    csvfile.seek(0, SEEK_SET)
    data = csvfile.read()
    print(data)

