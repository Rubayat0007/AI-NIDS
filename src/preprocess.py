import pandas as pd
import numpy as np


def clean_dataset(df):
    """
    Clean raw network traffic data.
    """

    print("=" * 60)
    print("Starting Data Preprocessing")
    print("=" * 60)

    # Remove duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)

    print(f"Removed duplicates: {before - after}")

    # Replace infinite values
    df = df.replace([np.inf, -np.inf], np.nan)

    # Handle missing values
    numeric_columns = df.select_dtypes(
        include=[np.number]
    ).columns

    categorical_columns = df.select_dtypes(
        exclude=[np.number]
    ).columns

    for column in numeric_columns:
        df[column] = df[column].fillna(
            df[column].median()
        )

    for column in categorical_columns:
        if df[column].isnull().any():
            mode = df[column].mode()

            if not mode.empty:
                df[column] = df[column].fillna(
                    mode.iloc[0]
                )
            else:
                df[column] = df[column].fillna("Unknown")

    print(f"Missing values after cleaning: {df.isnull().sum().sum()}")
    print(f"Final dataset shape: {df.shape}")

    return df


def encode_categorical_features(df, label_column=None):
    """
    Convert categorical features into numerical values.
    """

    df = df.copy()

    categorical_columns = df.select_dtypes(
        include=["object", "category", "bool"]
    ).columns.tolist()

    if label_column in categorical_columns:
        categorical_columns.remove(label_column)

    if categorical_columns:
        df = pd.get_dummies(
            df,
            columns=categorical_columns,
            drop_first=True,
            dtype=int
        )

    return df


def prepare_features(df, label_column):
    """
    Separate input features (X) and target label (y).
    """

    if label_column not in df.columns:
        raise ValueError(
            f"Label column '{label_column}' not found in dataset."
        )

    X = df.drop(columns=[label_column])
    y = df[label_column]

    print("=" * 60)
    print("Feature Preparation")
    print("=" * 60)

    print(f"Features: {X.shape[1]}")
    print(f"Samples : {X.shape[0]}")
    print(f"Target  : {label_column}")

    return X, y


def preprocess_pipeline(df, label_column):
    """
    Complete preprocessing pipeline.
    """

    df = clean_dataset(df)

    df = encode_categorical_features(
        df,
        label_column=label_column
    )

    X, y = prepare_features(
        df,
        label_column
    )

    return X, y


if __name__ == "__main__":
    print("AI-NIDS Preprocessing Module")
    print("Module is ready.")