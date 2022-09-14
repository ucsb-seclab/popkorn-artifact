import os
import ipdb
from util import fully_normalized_drivername
import config
from collections import defaultdict, Counter
import pickle
from pathlib import Path

from contextlib import contextmanager

@contextmanager
def pickle_backed(filename, default):
    # Code to acquire resource, e.g.:
    value = default
    if os.path.isfile(filename):
        with open(filename, 'rb') as f:
            value = pickle.load(f)
    try:
        yield value
    finally:
        with open(filename, 'wb') as f:
            pickle.dump(value, f)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('dataset', choices=list(config.CONFIGS.keys()))
    ARGS = parser.parse_args()

    # ipdb.set_trace()
    driver_paths = list(config.CONFIGS[ARGS.dataset]['driver_generator']())

    # with pickle_backed('.manual_dedup_state.pkl', Counter()) as counter:
    if True:
        counter: Counter = Counter()
        for driver_path in driver_paths:
            name = driver_path.name
            # if fully_normalized_drivername(name).startswith('rimspe'):
            #     ipdb.set_trace()
            normalized = fully_normalized_drivername(name)
            counter.update([normalized])
        # for val, count in sorted(counter.items()):
        for val, count in counter.most_common():
            print(f"{val}: {count}")
        duplicate_drivers = len([c for v, c in counter.most_common() if c > 1])
        print(f"{len(counter)}/{len(driver_paths)} unique drivers, {duplicate_drivers} had multiple versions")