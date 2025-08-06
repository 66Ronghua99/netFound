#!/bin/bash
set -e
set +x

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 input_folder output_folder"
    exit 1
fi

# Get the directory where the current script is located
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

input_folder="$1"
output_folder="$2"

mkdir -p "$output_folder"

# Check if Python script exists
python_script="$script_dir/python_preprocess.py"
if [ ! -f "$python_script" ]; then
    echo "Error: python_preprocess.py script not found in $script_dir"
    exit 1
fi

# Process all pcap files in parallel
find "$input_folder" -type f \( -name "*.pcap" -o -name "*.pcapng" \) | \
parallel "python3 $python_script --input_folder {} --output_folder $output_folder --step filter" 