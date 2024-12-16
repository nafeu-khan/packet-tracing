# **Network Traffic Data Parser and Visualizer**

---

## **Features**
- Parses network traffic data from CSV files.
- Supports filtering data by:
  - **Year** range (`--start`, `--end`).
  - **Month** range (`--startmonth`, `--endmonth`).
  - **Day** range (`--startday`, `--endday`).
- Aggregates statistics:
  - Total Traces
  - Total Packets
  - Total Trace Size (GB)
  - Total Transferred Bytes (TB)
  - Total IP Packets
  - Total IP6 Packets
- Plots all statistics on a single graph (e.g., `Total Traces`).

---

## **Directory Structure**

set start year and end_year in the file 

```plaintext
    root/HSPR/mawi_crawling.py
```

then run 
```python 
    python mawi_crawling.py 
```
then created extracted_data folder with the following directory structure.

The script expects data in the following format:

```plaintext
extracted_data/
    ├── 2022/
    │   ├── 01/
    │   │   ├── 01/
    │   │   │   ├── file1-total.csv
    │   │   │   ├── file2.csv
    │   │   ├── 02/
    │   │       ├── file3-total.csv
    ├── 2023/
    │   ├── 02/
    │       ├── 15/
    │       │   ├── file4-total.csv
```
---

run this command with specific time arg in the commmand 
```shell
python mawi_command.py -t -s 2022 -e 2023

python mawi_command.py -t -s 2023 -e 2023 -sm 11 -em 12

python mawi_command.py -t -s 2023 -e 2023 -sm 11 -em 11 -sd 1 -ed 5
```

---
## output 

```plaintext

2023-11: {'Total Traces': 10, 'Total Packets': 100000, 'Total Trace Size (GB)': 50.5, ...}
```

---
## Graph
graph will be in the mawi_graphs folder 
```plaintext
mawi_graphs/
    ├── combined_statistics_over_year.png
    ├── combined_statistics_over_month.png
    ├── combined_statistics_over_day.png

```
