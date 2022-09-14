# popkorn-artifact

## Artifact Evaluation Abstract
[Requirement description](https://www.acsac.org/2022/submissions/papers/artifacts/)

### Paper Title
POPKORN: Popping Windows Kernel Drivers At Scale

### Artifact Summary
The artifact for this submission contains
1. The dataset of drivers (the SYS files ending in the .sys extension) used for the evaluation in Section 6 of the paper, about 300MB in size
2. The python source-code of the `angr`-based analysis code used to produce the vulnerability reports used for the evaluation
3. A `Dockerfile` describing the evaluation environment with all dependencies and required tools installed
4. Detailed instructions and scripts to reproduce the performed evaluation results

The overall evaluation environment was
1. Ubuntu 20.04.4 LTS
2. Python 3.8.10
3. angr 9.1

### Notes
This evaluation can take significant time and computational resources to reproduce. For the evaluation in the paper we ran the analysis with a timeout of 1 hour per driver, and 8 drivers being analyzed concurrently. The final results took around 14 hours to complete analysis with these settings on a machine with an Intel Xeon CPU @ 2.40GHz with 24 cores and 94 GBs of RAM.

We separately reran the evaluation on a 96-core Intel Xeon Gold 6252 CPU @ 2.10GHz with 376 GB RAM machine with 48 drivers being analyzed in parallel, which brings the analysis time down to around 2.5 hours.

### Reproducing results

See the results in [the evaluation/ README](evaluation/README.md)