""" Converts TLDB requirement data to test files """

import os
import re
import csv
from typing import List

import typer

VULNERABLE_OUTDIR = "applicable"
SECURE_OUTDIR = "nonapplicable"

VULNERABLE_RE = re.compile(r"Vulnerable example(?: #\d)? -\s*```(.+?)```", re.DOTALL)
SECURE_RE = re.compile(r"Secure example(?: #\d)? -\s*```(.+?)```", re.DOTALL)


def handle_row(row: List[str], output_dir: str):
    name, _, md = row

    print(f"Converting {name}...")

    # Get test data from implementation
    vulnerable = VULNERABLE_RE.findall(md)[0].strip()
    secure = SECURE_RE.findall(md)[0].strip()

    # Write test file
    fname = name.lower().replace(".", "_").replace("-", "_") + ".tf"
    with open(os.path.join(output_dir, SECURE_OUTDIR, fname), "w") as f:
        f.write(secure)

    with open(os.path.join(output_dir, VULNERABLE_OUTDIR, fname), "w") as f:
        f.write(vulnerable)


def main(reqs_csv: str, output_dir: str):
    """
    reqs_csv should contain the exported output of the following query -
    SELECT name, importance, implementation_markdown FROM threats_requirement WHERE name LIKE 'REQ.SW.TERRAFORM%'
    """
    # Create output dirs
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
        os.mkdir(os.path.join(output_dir, SECURE_OUTDIR))
        os.mkdir(os.path.join(output_dir, VULNERABLE_OUTDIR))

    # Read the requirements CSV
    with open(reqs_csv, newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        next(csvreader)  # Skip header
        for row in csvreader:
            handle_row(row, output_dir)

    print("!!!DONE!!!")


if "__main__" == __name__:
    typer.run(main)