import pandas as pd
import argparse
import os

def convert_pkl_to_baseline(dataset: str):
    """Convert train_logs.pkl to baseline CSV for deviation analysis.
    
    Args:
        dataset: Name of the dataset (e.g., 'cadets')
    """
    input_file = f'data/raw/{dataset}/train_logs.pkl'
    output_file = f'baseline_{dataset}.csv'
    
    if not os.path.exists(input_file):
        raise FileNotFoundError(
            f"Input file not found: {input_file}\n"
            f"Make sure you've run parser.py first."
        )
    
    print(f"Loading {input_file}...")
    df = pd.read_pickle(input_file)
    
    print(f"Loaded {len(df)} records")
    print(f"Columns: {list(df.columns)}")
    
    # Deduplicate based on processUUID, objectUUID, event
    dedup_columns = ['processUUID', 'objectData', 'event']
    original_count = len(df)
    df = df.drop_duplicates(subset=dedup_columns)
    dedup_count = len(df)
    
    print(f"Deduplicated: {original_count} → {dedup_count} records")
    print(f"  Removed {original_count - dedup_count} duplicate entries")
    
    print(f"Saving to {output_file}...")
    df.to_csv(output_file, index=False)
    
    print(f"✓ Baseline file created: {output_file}")
    print(f"  Total records: {len(df)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Convert train_logs.pkl to baseline CSV for deviation analysis'
    )
    parser.add_argument(
        'source', 
        type=str, 
        help='Dataset name (e.g., cadets)'
    )
    
    args = parser.parse_args()
    convert_pkl_to_baseline(args.source)