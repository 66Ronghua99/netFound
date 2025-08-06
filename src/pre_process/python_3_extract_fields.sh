#!/bin/bash
set -e
set +x

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 input_folder output_folder [tcpoptions]"
    exit 1
fi

# Get the directory where the current script is located
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

input_folder="$1"
output_folder="$2"
tcpoptions=0
if [ "$#" -eq 3 ]; then
    tcpoptions="$3"
fi

# Check if input_folder exists and is a directory
if [ ! -d "$input_folder" ]; then
    echo "Error: Input folder '$input_folder' does not exist or is not a directory."
    exit 1
fi

# Create the output folder if it doesn't exist
mkdir -p "$output_folder"

# Check if Python script exists
python_script="$script_dir/python_preprocess.py"
if [ ! -f "$python_script" ]; then
    echo "Error: python_preprocess.py script not found in $script_dir"
    exit 1
fi

# Create output directories for each subdirectory in the input folder
find "$input_folder" -mindepth 1 -maxdepth 1 -type d -print0 | while IFS= read -r -d '' dir; do
    dir_name="$(basename "$dir")"
    mkdir -p "$output_folder/$dir_name"
done

# Process all flow directories in parallel
find "$input_folder" -mindepth 1 -maxdepth 1 -type d -print0 | \
parallel -0 "python3 $python_script --input_folder {} --output_folder $output_folder/{/} --step extract $([ $tcpoptions -eq 1 ] && echo '--tcp_options')" 