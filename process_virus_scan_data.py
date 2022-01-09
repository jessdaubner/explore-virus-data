#!/usr/local/bin/python3
"""Script to flatten and clean test virus scan data.

   Args:
     data_dir (str): directory where VirusTotal-like JSON data resides
     save_output (bool): whether to write the processed data to a local CSV file 

   Usage:
     python process_virus_scan_data.py <data_dir> True/False
     ./process_virus_scan_data.py data False
"""
import os
import json
import pytz
import typer
import smart_open
import pandas as pd
from datetime import datetime

# Traditional vendors whose scan results we want to use
VENDORS = ["Microsoft", "Symantec", "BitDefender", "McAfee"]


def get_data_files(data_dir: str) -> list[str]:
    """Searches local directory for JSON data files and generates absolute
    path for each JSON file found.
    """
    json_files = [
        os.path.abspath(f"{data_dir}/{file}")
        for file in os.listdir(data_dir)
        if file.endswith(".json")
    ]
    if len(json_files) < 1:
        raise (
            f"""{data_dir} does not contain .json files. Please provide a valid directory."""
        )
    return json_files


def format_date_utc(date: str, timezone: str = None) -> datetime.date:
    """Given a timezone, formats a timestamp str as UTC; otherwise,
    simply returns datetime object for latter comparison.

    Note, it's not clear what timezone source data was caputured in
    and we may want to assume its in UTC.
    """
    formatted_date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")

    if timezone:
        utc = pytz.utc
        original_timezone = pytz.timezone(timezone)
        formatted_date = original_timezone.localize(formatted_date)
        formatted_date = formatted_date.astimezone(utc)
    return formatted_date


def calculate_detections_by_vendors(data: dict, vendors: list) -> dict:
    """For select vendors, calculate total detections per scan.
    Adds key for each vendor and 'total_detections' to dictionary in-place.
    """
    data["total_detections"] = 0
    for d in data["scans"].items():
        if d[0] in vendors:
            data[d[0]] = 1 if d[1]["detected"] else 0
            if d[1]["detected"]:
                data["total_detections"] += 1
    del data["scans"]
    return data


def calculate_date_diffs(data: dict) -> dict:
    """Calculate time difference between scan_data and first/last_seen in days"""
    data["diff_first_seen"] = (data["scan_date"] - data["first_seen"]).days
    data["diff_last_seen"] = (data["scan_date"] - data["last_seen"]).days
    return data


def clean_scan(data: dict) -> dict:
    """Executes all preprocessing steps to clean scan data"""
    data = calculate_detections_by_vendors(data, VENDORS)

    for date_field in ["scan_date", "first_seen", "last_seen"]:
        data[date_field] = format_date_utc(data[date_field])
    calculate_date_diffs(data)
    return data


def main(data_dir: str, save_output: bool) -> None:
    clean_scans = []
    data_files = get_data_files(data_dir)
    for filename in data_files:
        print(f"Processing data for {filename}")
        with open(filename) as file:
            scan_data = json.load(file)
        cleanned_scan = clean_scan(scan_data)
        clean_scans.append(cleanned_scan)

    scans_df = pd.DataFrame(clean_scans)
    print("Correlation matrix of 'detection' results by vendor:")
    print(f"\t{scans_df[VENDORS].corr()}")

    if save_output:
        print(f"Saving {scans_df.shape[0]} processed records to scan.csv.")
        scans_df.to_csv("scans.csv")


if __name__ == "__main__":
    typer.run(main)
