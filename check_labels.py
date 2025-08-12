#!/usr/bin/env python3

import os
import sys
sys.path.append('src/train')

from datasets import load_dataset
from collections import Counter

def check_labels():
    train_dir = "/home/ronghua/codes/netFound/data/ISCVPN2016/final/shards"
    
    print("Loading dataset...")
    train_dataset = load_dataset(
        "arrow",
        data_dir=train_dir,
        split="train",
        cache_dir="/tmp",
        streaming=False,
    )
    
    print(f"Dataset loaded. Total samples: {len(train_dataset)}")
    print(f"Available columns: {train_dataset.column_names}")

    print(train_dataset["flow_duration"])
    
    # Print first row with 'chat' label
    if "labels" in train_dataset.column_names:
        labels = train_dataset["labels"]
        chat_indices = [i for i, label in enumerate(labels) if label == "chat"]
        if chat_indices:
            first_chat_index = chat_indices[0]
            print(f"\n=== FIRST ROW WITH 'CHAT' LABEL (index {first_chat_index}) ===")
            first_chat_row = train_dataset[first_chat_index]
            for column, value in first_chat_row.items():
                print(f"{column}: {value}")
        else:
            print("\nNo 'chat' label found in the dataset!")
    
    if "labels" in train_dataset.column_names:
        print("\n=== LABEL ANALYSIS ===")
        labels = train_dataset["labels"]
        unique_labels = set(labels)
        
        print(f"Total samples: {len(labels)}")
        print(f"Unique labels: {sorted(unique_labels)}")
        print(f"Number of unique labels: {len(unique_labels)}")
        
        # Count frequency of each label
        label_counts = Counter(labels)
        print("\nLabel distribution:")
        for label, count in sorted(label_counts.items()):
            percentage = count/len(labels)*100
            print(f"  Label {label}: {count} samples ({percentage:.1f}%)")
        
        return len(unique_labels)
    else:
        print("No 'labels' column found in dataset!")
        return None

if __name__ == "__main__":
    num_labels = check_labels()
    if num_labels:
        print(f"\nRecommended num_labels: {num_labels}")
