# Datasets

The datasets for POPKORN, `popkorn_drivers_with_sink_imports_only` is the one used in the Evaluation in Section 6 of the paper.

## CVE_sure
Drivers contained in the POPKORN dataset mentioned in CVEs where I am sure they are vulnerable

## CVE_unsure
Drivers mentioned in the POPKORN dataset in CVEs where I am unsure if they are vulnerable or if they are the exact driver mentioned

## physmem_drivers

Drivers from the [physmem_drivers](https://github.com/namazso/physmem_drivers) github repository

## physmem_drivers_imports_only

The drivers from the `physmem_drivers`, filtered by only keeping WDM drivers importing `ZwOpenProcess, ZwMapViewOfSection, MmMapIoSpace`

## popkorn_drivers_with_sink_imports_only

WDM drivers in the POPKORN dataset importing `ZwOpenProcess, ZwMapViewOfSection, MmMapIoSpace`

