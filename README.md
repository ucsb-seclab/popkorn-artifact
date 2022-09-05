# popkorn-artifact

## Artifact Evaluation Abstract
[Requirement description](https://www.acsac.org/2022/submissions/papers/artifacts/)

### Paper Title
POPKORN: Popping Windows Kernel Drivers At Scale

### Artifact Summary
The artifact for this submission will contain
1. The (full/filtered?) collected dataset of drivers (files ending in the .sys extension) used for the evaluation in Paper Section ?
2. The python source-code of the `angr`-based analysis code used to perform the evaluation and produce the vulnerability reports used for the evaluation
3. A `Dockerfile` to run the analysis in with all dependencies and required tools installed
4. Detailed instructions and scripts to reproduce the performed analysis commands

The overall evaluation environment was 
1. Ubuntu 20.04
2. Python 3.8
3. angr from git

### Notes
This evaluation can take significant time and computational resources to reproduce. For the evaluation we ran the analysis with
1. timeouts of 1 hour
2. a machine with 64GB of RAM
3. (1/4) analysis runs at a time (don't remember if i parallelized at all, I don't think I did)


### TODO
add high-level information about size, schema format
