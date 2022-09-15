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

### Local Install

On Ubuntu 20.04, the required dependencies can be installed with

```
apt-get install git build-essential python3 python3-pip python3-dev htop vim sudo openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 libc6:i386 libssl-dev nasm binutils-multiarch qtdeclarative5-dev libpixman-1-dev libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake libffi-dev libxslt1-dev libxml2-dev

pip install virtualenvwrapper

# inside the virtualenv if you choose to use one
pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9
```
