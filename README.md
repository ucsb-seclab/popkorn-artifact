# popkorn-artifact

## Artifact Evaluation Abstract
[Requirement description](https://www.acsac.org/2022/submissions/papers/artifacts/)

### Paper Title
POPKORN: Popping Windows Kernel Drivers At Scale

### Artifact Summary
The artifact for this submission will contain
1. The full and filtered collected dataset of drivers (files ending in the .sys extension) used for the evaluation in Paper Section 6
2. The python source-code of the `angr`-based analysis code used to produce the vulnerability reports used for the evaluation
3. A `Dockerfile` to run the analysis in with all dependencies and required tools installed
4. Detailed instructions and scripts to reproduce the performed analysis commands

The overall evaluation environment was 
1. Ubuntu 20.04.4 LTS
2. Python 3.8.10
3. angr 9.1

### Notes
This evaluation can take significant time and computational resources to reproduce. For the evaluation we ran the analysis with
1. a timeout of 1 hour per driver
2. 8 drivers analyzed concurrently

