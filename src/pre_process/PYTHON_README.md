# Python Implementation of NetFound Preprocessing

This directory contains a Python implementation of the NetFound data preprocessing pipeline, providing Python equivalents of the C++ preprocessing tools.

## Overview

The Python implementation includes:

1. **`python_preprocess.py`** - Main Python script that implements all preprocessing steps
2. **`python_1_filter.sh`** - Shell wrapper for packet filtering
3. **`python_2_pcap_splitting.sh`** - Shell wrapper for flow splitting  
4. **`python_3_extract_fields.sh`** - Shell wrapper for field extraction
5. **`requirements.txt`** - Python dependencies

## Features

### ✅ **Complete Compatibility**
- **Binary Format**: Produces identical binary output to C++ implementation
- **Field Extraction**: Matches exact field structure and byte ordering
- **Sequence Normalization**: Implements same TCP sequence number logic
- **Protocol Support**: TCP, UDP, and ICMP with proper field extraction

### ✅ **Enhanced Features**
- **Error Handling**: Robust error handling with detailed logging
- **Parallel Processing**: Supports parallel processing of multiple files
- **Flexible Input**: Handles both individual files and directories
- **Fallback Support**: Can use pyshark if scapy is not available

## Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Make shell scripts executable
chmod +x python_*.sh
```

## Usage

### Complete Pipeline
```bash
# Process entire directory through all steps
python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output

# With TCP options
python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output --tcp_options
```

### Individual Steps
```bash
# Step 1: Filter packets
python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output --step filter

# Step 2: Split by flows  
python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output --step split

# Step 3: Extract fields
python python_preprocess.py --input_folder /path/to/input --output_folder /path/to/output --step extract
```

### Using Shell Wrappers
```bash
# Use shell wrappers (same interface as C++ version)
./python_1_filter.sh input_folder output_folder
./python_2_pcap_splitting.sh input_folder output_folder  
./python_3_extract_fields.sh input_folder output_folder [tcpoptions]
```

## Data Format Compatibility

### Binary Output Format
The Python implementation produces **identical binary output** to the C++ version:

```
[Protocol Byte (1/6/17)] + [Packet₀] + [Packet₁] + ... + [Packetₙ]
```

### Packet Structure
Each packet follows the exact same structure as the C++ implementation:

**Common Fields (all protocols):**
- `uint64_t`: Unix timestamp with nanoseconds
- `uint8_t`: IP header length
- `uint8_t`: Type of Service
- `uint16_t`: Total length (little-endian)
- `uint8_t`: IP flags
- `uint8_t`: TTL
- `uint32_t`: Source IP (little-endian)
- `uint32_t`: Destination IP (little-endian)

**Protocol-Specific Fields:**
- **TCP**: Source/Destination ports, TCP flags, window size, sequence/acknowledgment numbers (relative), urgent pointer
- **UDP**: Source/Destination ports, UDP length
- **ICMP**: ICMP type, ICMP code

**All protocols**: 12 bytes of payload padding

## Key Implementation Details

### 1. **Byte Ordering**
- All multi-byte values are converted to little-endian (matching C++ implementation)
- IP addresses are converted to little-endian integers
- Port numbers, sequence numbers, and lengths are byte-swapped

### 2. **TCP Sequence Normalization**
- Implements identical logic to C++ version
- Tracks absolute sequence numbers from first packet
- Normalizes relative sequence numbers for both directions

### 3. **TCP Flags Extraction**
- Maps TCP flags to bit positions exactly like C++ implementation
- CWR(7), ECE(6), URG(5), ACK(4), PSH(3), RST(2), SYN(1), FIN(0)

### 4. **Flow Splitting**
- Uses 5-tuple: (src IP, dst IP, src port, dst port, protocol)
- Handles ICMP flows with port 0
- Maintains packet ordering within flows

## Advantages Over C++ Implementation

1. **Easier Debugging**: Python's rich error messages and debugging tools
2. **Cross-Platform**: Works on macOS, Linux, and Windows without recompilation
3. **Extensibility**: Easy to modify and extend functionality
4. **Dependency Management**: Simple pip-based dependency management
5. **Integration**: Seamless integration with Python ML workflows

## Performance Considerations

- **Memory Usage**: Processes files in chunks to manage memory
- **Parallel Processing**: Supports parallel processing of multiple files
- **Optimized Parsing**: Uses scapy's optimized packet parsing
- **Binary Output**: Direct binary writing for maximum performance

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Permission Errors**
   ```bash
   chmod +x python_*.sh
   ```

3. **Large File Processing**
   - The implementation handles large files by processing packets in memory-efficient chunks
   - For very large files, consider splitting them first

4. **Protocol Detection Issues**
   - The implementation strictly validates protocol consistency within flows
   - Mixed protocols in a single flow will be logged as warnings

## Integration with Existing Pipeline

The Python implementation can be used as a **drop-in replacement** for the C++ tools:

```bash
# Replace C++ tools with Python equivalents
export FILTER_SCRIPT="./python_1_filter.sh"
export SPLIT_SCRIPT="./python_2_pcap_splitting.sh"  
export EXTRACT_SCRIPT="./python_3_extract_fields.sh"

# Use in existing scripts
$FILTER_SCRIPT input_folder output_folder
$SPLIT_SCRIPT input_folder output_folder
$EXTRACT_SCRIPT input_folder output_folder
```

The output files will be **identical** to the C++ version and can be processed by the existing `Tokenize.py` script without any modifications. 