# Explore Virsus Data
Quick script to explore security scan data similar to VirusTotal.

## Getting Started 
1. Install the project's dependencies using `requirements.txt` or `pyproject.toml` with your preferred tool (poetry, pipenv, pdm, venv, pip, etc.). 
2. Once you have an active virtual environment, the script can be run as follows:
   ```
   python process_virus_scan_data.py <data_dir> <save_output>
   ```
   where `data_dir` is where the `*.json` virus scan data is available locally and `save_output` is a boolean value that determines if the process results are saved.

### Example Output
```
./process_virus_scan_data.py data True
Processing data for /Users/jessiedaubner/dev/virus-data-eda/data/report_0.json
Processing data for /Users/jessiedaubner/dev/virus-data-eda/data/report_1.json
Processing data for /Users/jessiedaubner/dev/virus-data-eda/data/report_4.json
Processing data for /Users/jessiedaubner/dev/virus-data-eda/data/report_2.json
Processing data for /Users/jessiedaubner/dev/virus-data-eda/data/report_3.json
Correlation matrix of 'detection' results by vendor:
	     Microsoft  Symantec  BitDefender    McAfee
Microsoft     1.000000  0.612372     1.000000  0.612372
Symantec      0.612372  1.000000     0.612372  1.000000
BitDefender   1.000000  0.612372     1.000000  0.612372
McAfee        0.612372  1.000000     0.612372  1.000000
Saving 5 processed records to scan.csv.
```

## Testing
`pytest`
