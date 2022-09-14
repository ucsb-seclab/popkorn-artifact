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