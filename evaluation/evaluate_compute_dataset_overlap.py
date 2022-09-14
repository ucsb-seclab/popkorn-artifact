import functools
import hashlib
from lib2to3.pgen2 import driver
import os
import re
import shutil
import subprocess
import angr
import archinfo
import cle
import sys
import time
import editdistance

from multiprocessing.pool import Pool
from pathlib import Path
from os.path import join

import config

def sha(path):
    with open(path, 'rb') as f:
        d = f.read()
        return hashlib.sha256(d).hexdigest()

POPKORN_DIR = Path('../datasets/popkorn_drivers_with_sink_imports_only').absolute().resolve()
PHYSMEM_DIR = Path('../datasets/physmem_drivers_imports_only').absolute().resolve()

DRIVER_NAMES_POPKORN = os.listdir(str(POPKORN_DIR))
DRIVER_NAMES_PHYSMEM = os.listdir(str(PHYSMEM_DIR))

SHA_TO_DRIVER_PHYSMEM = {sha(PHYSMEM_DIR / d): d for d in DRIVER_NAMES_PHYSMEM}
SHA_TO_DRIVER_POPKORN = {sha(POPKORN_DIR / d): d for d in DRIVER_NAMES_POPKORN}

SHAS_PHYSMEM = set(SHA_TO_DRIVER_PHYSMEM.keys())
SHAS_POPKORN = set(SHA_TO_DRIVER_POPKORN.keys())

SHAS_SHARED = SHAS_PHYSMEM.intersection(SHAS_POPKORN)

print(f"By SHA: physmem = {len(SHAS_PHYSMEM)}, shared = {len(SHAS_SHARED)}, popkorn = {len(SHAS_POPKORN)}")
print("Shared:")
for sha in SHAS_SHARED:
    popkorn = SHA_TO_DRIVER_POPKORN[sha]
    physmem = SHA_TO_DRIVER_PHYSMEM[sha]
    print(f'\t{popkorn=} {physmem=}')


DRIVER_NAMES_PHYSMEM_CLEAN = set()
DRIVER_NAMES_POPKORN_CLEAN = set()

for driver_name in DRIVER_NAMES_PHYSMEM:
    driver_name_clean = driver_name
    if match := re.fullmatch('(.*)_[0-9a-fA-F]{64}.sys', driver_name):
        # print(repr(match.groups))
        driver_name_clean = match.groups()[0] + '.sys'
    driver_name_clean = driver_name_clean.lower()
    driver_name_clean = driver_name_clean.replace('amd64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('x64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('x86.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('i386.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('86.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('32.sys', '.sys')
    DRIVER_NAMES_PHYSMEM_CLEAN.add(driver_name_clean)
    # DRIVER_NAMES_PHYSMEM_CLEAN.add(driver_name_clean[:-4] + '64.sys')
    # DRIVER_NAMES_PHYSMEM_CLEAN.add(driver_name_clean[:-4] + '32.sys')
    # DRIVER_NAMES_PHYSMEM_CLEAN.add(driver_name_clean[:-4] + 'x64.sys')
    # DRIVER_NAMES_PHYSMEM_CLEAN.add(driver_name_clean[:-4] + 'x86.sys')

for driver_name in DRIVER_NAMES_POPKORN:
    driver_name_clean = driver_name
    if match := re.fullmatch('[0-9a-fA-F]{32}_(.*).sys', driver_name):
        # print(repr(match.groups()))
        driver_name_clean = match.groups()[0] + '.sys'
    driver_name_clean = driver_name_clean.lower()
    driver_name_clean = driver_name_clean.replace('amd64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('x64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('x86.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('i386.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('86.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('64.sys', '.sys')
    driver_name_clean = driver_name_clean.replace('32.sys', '.sys')
    DRIVER_NAMES_POPKORN_CLEAN.add(driver_name_clean)
    # DRIVER_NAMES_POPKORN_CLEAN.add(driver_name_clean[:-4] + '64.sys')
    # DRIVER_NAMES_POPKORN_CLEAN.add(driver_name_clean[:-4] + '32.sys')
    # DRIVER_NAMES_POPKORN_CLEAN.add(driver_name_clean[:-4] + 'x64.sys')
    # DRIVER_NAMES_POPKORN_CLEAN.add(driver_name_clean[:-4] + 'x86.sys')

DRIVER_NAMES_CLEAN_SHARED = DRIVER_NAMES_PHYSMEM_CLEAN.intersection(DRIVER_NAMES_POPKORN_CLEAN)

print(f'physmem = {list(sorted(DRIVER_NAMES_PHYSMEM_CLEAN))}\n')
print(f'popkorn = {list(sorted(DRIVER_NAMES_POPKORN_CLEAN))}\n')
print(f'shared = {DRIVER_NAMES_CLEAN_SHARED=}\n')

print(f'By Name: physmem = {len(DRIVER_NAMES_PHYSMEM_CLEAN)}, shared = {len(DRIVER_NAMES_CLEAN_SHARED)}, popkorn = {len(DRIVER_NAMES_POPKORN_CLEAN)}')
print("Shared:")
for name in DRIVER_NAMES_CLEAN_SHARED:
    print(f'\t{name}')

for name in DRIVER_NAMES_PHYSMEM_CLEAN:
    closest_5 = list(sorted(DRIVER_NAMES_POPKORN_CLEAN, key=lambda x: editdistance.distance(x, name)))[:5]
    print(f"{name=} : {closest_5=}")