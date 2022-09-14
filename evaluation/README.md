# Reproducing the Evaluation of POPKORN

The results of POPKORN's evaluation can be reproduced by running the following commands in the provided Docker container

```
cd evaluation/

for i in `seq 1 5`
do
    python runner_analysis.py --parallel 8 --timeout 60 popkorn_drivers_with_sink_imports_only
done

python export_results_to_csv.py ./results_popkorn_drivers_with_sink_imports_only_timeout3600_run*

# to get the number of drivers with each import
python evaluate_count_imports.py popkorn_drivers_with_sink_imports_only

#
python evaluate_compute_bug_types.py
```


## Reproduced results
We reran the results with this exact setup in two setups

### Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz, 96 cores, 378 GB RAM

Machine Specs:
```
$ lscpu
Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   46 bits physical, 48 bits virtual
CPU(s):                          96
On-line CPU(s) list:             0-95
Thread(s) per core:              2
Core(s) per socket:              24
Socket(s):                       2
NUMA node(s):                    2
Vendor ID:                       GenuineIntel
CPU family:                      6
Model:                           85
Model name:                      Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz
Stepping:                        7
CPU MHz:                         2967.620
CPU max MHz:                     3700.0000
CPU min MHz:                     1000.0000
BogoMIPS:                        4200.00
Virtualization:                  VT-x
L1d cache:                       1.5 MiB
L1i cache:                       1.5 MiB
L2 cache:                        48 MiB
L3 cache:                        71.5 MiB
NUMA node0 CPU(s):               0-23,48-71
NUMA node1 CPU(s):               24-47,72-95
...

$ free -h
              total        used        free      shared  buff/cache   available
Mem:          376Gi       343Gi        32Gi       0.0Ki       963Mi        31Gi
Swap:         8.0Gi       8.0Gi       4.0Mi
```

On this machine, the following command finished in 156 minutes (2h, 36 minutes):
```
$ time python runner_analysis.py --timeout 3600 popkorn_drivers_with_sink_imports_only
...

real    156m3.492s
user    3661m43.074s
sys     133m22.671s
```

####

Time taken until vulnerable drivers were detected
```
$ python ./evaluate_time_taken.py ./results_popkorn_drivers_with_sink_imports_only_timeout3600_run0/ | sed 's/,/ /g' | awk '{print $3}' | sort -n
WARNING | 2022-09-14 14:16:44,356 | angr.state_plugins.unicorn_engine | failed loading "angr_native.so", unicorn support disabled (/home/popkorn/angr-dev/angr/angr/lib/lib/angr_native.so: cannot open shared object file: No such file or directory)

time_taken
6.868677377700806
7.350770711898804
7.376057147979736
7.394596338272095
7.78324031829834
8.119671821594238
8.332800388336182
8.52816367149353
8.98337459564209
9.341598987579346
9.346211671829224
9.602535247802734
9.60722279548645
10.094849586486816
10.1289381980896
10.299698114395142
10.651638984680176
10.693922758102417
11.223162651062012
11.84817361831665
11.84817361831665
11.932438135147095
12.590117931365967
12.594189167022705
12.594189167022705
13.20697569847107
14.17812442779541
16.13493275642395
16.687831163406372
18.640488147735596
18.640488147735596
22.37536358833313
28.012099027633667
30.82571792602539
33.472400426864624
33.95105051994324
38.7646427154541
41.89842867851257
62.94983887672424
142.70665001869202
```

Vulnerabilities detected
```
$ python ./evaluate_compute_bug_types.py ./results_popkorn_drivers_with_sink_imports_only_timeout3600_run0/
WARNING | 2022-09-14 14:19:49,379 | angr.state_plugins.unicorn_engine | failed loading "angr_native.so", unicorn support disabled (/home/popkorn/angr-dev/angr/angr/lib/lib/angr_native.so: cannot open shared object file: No such file or directory)
driver_name,triggered_sink_function
ATSwpDrv.sys,MmapIoSpace
AsIO32.sys,ZwMapViewOfSection
AsIO64.sys,ZwMapViewOfSection
AsInsHelp32.sys,ZwMapViewOfSection
AsInsHelp64.sys,ZwMapViewOfSection
AsUpIO32.sys,ZwMapViewOfSection
AsUpIO64.sys,ZwMapViewOfSection
AsmIo.sys,MmapIoSpace
AsmIo64.sys,MmapIoSpace
CorsairLLAccess32.sys,MmapIoSpace
CorsairLLAccess64.sys,MmapIoSpace
EIO64.sys,MmapIoSpace
FLASHUD.sys,MmapIoSpace
GPCIDrv.sys,MmapIoSpace
GPCIDrv.sys,ZwMapViewOfSection
GPCIDrv64.sys,MmapIoSpace
GPCIDrv64.sys,ZwMapViewOfSection
Mydrivers32.sys,MmapIoSpace
PhlashNT.sys,MmapIoSpace
QIOMem.sys,MmapIoSpace
WinFlash.sys,MmapIoSpace
WinFlash64.sys,MmapIoSpace
athpexnt.sys,MmapIoSpace
aticd64a.sys,ZwMapViewOfSection
atiicdxx.sys,ZwMapViewOfSection
cpuz_x32.sys,MmapIoSpace
dcdbas64.sys,MmapIoSpace
flash.sys,MmapIoSpace
l1v5gvnk.sys,ZwMapViewOfSection
nvflsh32.sys,ZwMapViewOfSection
nvflsh64.sys,ZwMapViewOfSection
nvnetbus.sys,ZwMapViewOfSection
pmxdrv.sys,ZwMapViewOfSection
rtkio64.sys,MmapIoSpace
rtkiow8x64.sys,MmapIoSpace
rtkiow8x86.sys,MmapIoSpace
srvkp.sys,MmapIoSpace
srvkp.sys,ZwMapViewOfSection
```
