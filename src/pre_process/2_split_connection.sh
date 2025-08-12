#!/bin/bash

set -e
set +x

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 input_folder output_folder"
    exit 1
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

input_folder="$1"
output_folder="$2"
split_connection_script="$script_dir/2_split_connection"

mkdir -p "$output_folder"

find "$input_folder" -type f | parallel "mkdir -p $output_folder/{/.} && $split_connection_script {} $output_folder/{/.}/"
