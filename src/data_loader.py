import pandas as pd
from pathlib import Path


def load_dataset(file_path):
    """
    Load a network intrusion detection dataset.

    Supports CSV files.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    if file_path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path)
    else:
        raise ValueError(
            "Unsupported file format. Please use a CSV dataset."
        )

    print("=" * 60)
    print("Dataset loaded successfully")
    print("=" * 60)
    print(f"Rows    : {df.shape[0]}")
    print(f"Columns : {df.shape[1]}")
    print()

    return df


def show_dataset_info(df):
    """Display basic information about the dataset."""

    print("Dataset Information")
    print("-" * 60)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nMissing Values:")
    print(df.isnull().sum().sum())

    print("\nFirst 5 Rows:")
    print(df.head())

    print("\nData Types:")
    print(df.dtypes)


if __name__ == "__main__":
    print("AI-NIDS Data Loader")
    print("Module is ready.")