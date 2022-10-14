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

The overall evaluation environment consists of
1. Ubuntu 20.04.4 LTS
2. Python 3.8.10
3. angr 9.2.18

### Notes
This evaluation can take significant time and computational resources to reproduce. For the evaluation in the paper we ran the analysis with a timeout of 1 hour per driver, and 8 drivers being analyzed concurrently. The final results took around 14 hours to complete analysis with these settings on a machine with an Intel Xeon CPU @ 2.40GHz with 24 cores and 94 GBs of RAM.

We separately reran the evaluation on a 96-core Intel Xeon Gold 6252 CPU @ 2.10GHz with 376 GB RAM machine with 48 drivers being analyzed in parallel, which brings the analysis time down to around 2.5 hours.

### Reproducing results

Detailed instructions on how to reproduce the evaluation, as well as expected results can be found in [the evaluation/ README](evaluation/README.md).

### Docker Install

The docker container can either be built locally via `docker build -t popkorn .` from within the root directory of the repository, or
a prebuilt version can be downloaded from [DockerHub](https://hub.docker.com/layers/lukasdresel/popkorn/latest/images/sha256-5ce7a8a518b4142ce98ac2c79ab87170be51028ef151d8eab80c88af6c7e0dd5) via `docker pull lukasdresel/popkorn`.

### Local Install

On Ubuntu 20.04, the required dependencies can be installed with

```

dpkg --add-architecture i386

apt-get update

apt-get install git build-essential python3 python3-pip python3-dev htop vim sudo \
                openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 \
                libc6:i386 libssl-dev nasm binutils-multiarch qtdeclarative5-dev libpixman-1-dev \
                libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake \
                libffi-dev libxslt1-dev libxml2-dev

pip install virtualenvwrapper

# inside the virtualenv if you choose to use one
pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9
```

### Analysis on your own dataset

#### Full dataset
If you would like to run POPKORN on your own dataset of drivers, follow the following steps:
```
cd /path/to/popkorn/artifact/repo/
mkdir datasets/my_dataset
cp /path/to/my/kernel/drivers/*.sys ./datasets/my_dataset/
```

Then you can use `my_dataset` in the following commands to run the full analysis on your dataset with 8 parallel tasks and a 1 hour timeout per driver. This matches the evaluation we performed with the dataset name changed.
```
cd evaluation/

# In the evaluation we ran each analysis 5 times, for simplicity here we only do one 
python runner_analysis.py --parallel 8 --timeout 3600 my_dataset

# export results
python export_results_to_csv.py ./results_my_dataset_timeout3600_run*

# print out vulnerable driver info for your dataset
python evaluate_compute_bug_types.py './results_my_dataset_timeout3600_*'
```
#### Single Target
If you want to run the base analysis on a single driver yourself, you can instead run
```
workon popkorn # virtualenv setup with all dependencies
python angr_analysis/angr_full_blown.py /path/to/driver.sys
```

A run of this might look like this:

```
$ python angr_analysis/angr_full_blown.py ./datasets/physmem_drivers_imports_only/AsUpIO.sys 
Found WDM driver:  0x100060

Driver DEVICE_NAME:  \\\\.\\AsUpdateio

Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..

ZwOpenProcess import not found!

MmMapIoSpace import not found!

[+] Found ZwMapViewOfSection:  0x100030
DriverObject @ 0x444f0000

[+] Finding the IOCTL Handler..


<SimulationManager with 1 active> {'active': [<SimState @ 0x100018>]}
<SNIP, angr output ...>
...
[+] Found ioctl handler @ 11a10
<SimulationManager with 1 active>
<SNIP, angr output ...>
...
<SimulationManager with 1 active, 3 deadended, 1 found, 11 deferred>
Found sol early..

Finding the IOCTL codes..
[+] Boom! Here is the IOCTL:  0xa040a480
[+] IOCTL for ZwMapViewOfSection:  0xa040a480
[+] ZwMapViewOfSection is potentially vulnerable, mapping PhysicalMemory .. 
[+] Input Buffer Size:  <Bool InputBufferLength_15_32 >= 0x18>
[+] Output Buffer Size:  <Bool OutputBufferLength_14_32 >= 0x8>
[+] Input Buffer:  <Bool (0x0 .. (0x0 .. ioctl_inbuf_10_4096[79:64]) + ioctl_inbuf_10_4096[191:160]) + ioctl_inbuf_10_4096[127:64] - mem_7fffffffffefed0_31_64{UNINITIALIZED}[31:0] != 0x0>
```

This output shows that POPKORN detected a `ZwMapViewOfSection vulnerability with IOCTL 0xa040a480, when given an input buffer of size at least 24(0x18), and output size of at least 0x8. It also shows a constraint on certain bytes of the input buffer which must be satisfied for the vulnerability to be triggered.
