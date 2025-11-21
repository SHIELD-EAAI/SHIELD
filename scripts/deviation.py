import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib
import os

class DeviationAnalyzerFrequency:
    def __init__(self, dataset_name, file_name):
        self.dataset_name = dataset_name
        self.file_name = file_name
        self.directory_path = f'model_output_{dataset_name}_frequency'
        self.features = ['event', 'processName', 'objectData']
        self.duplicate_features = ['event', 'processUUID', 'objectData']
        self.frequency_maps = {}

    def frequency_encode(self, df, fit=False):
        """
        Encode categories by their frequency/rarity.
        Rare values get lower frequencies - perfect for anomaly detection!
        """
        df_encoded = df.copy()
        
        for col in self.features:
            if fit:
                # Calculate frequency of each category
                freq = df[col].value_counts(normalize=True)
                self.frequency_maps[col] = freq.to_dict()
            
            # Map to frequency (rare items get small values)
            df_encoded[col + '_freq'] = df_encoded[col].map(
                self.frequency_maps[col]
            ).fillna(0)  # Unseen categories get 0 (very rare)
        
        # Use frequency-encoded features
        feature_cols = [col + '_freq' for col in self.features]
        return df_encoded[feature_cols].values

    def train_lof(self, X_train, params):
        lof = LocalOutlierFactor(**params, novelty=True)
        lof.fit(X_train)
        return lof

    def test_lof(self, lof, X_test):
        outliers = lof.predict(X_test)
        return outliers

    def save_model_and_mappers(self, model, scaler):
        os.makedirs(self.directory_path, exist_ok=True)
        joblib.dump(model, os.path.join(self.directory_path, 'lof_model.joblib'))
        joblib.dump(scaler, os.path.join(self.directory_path, 'scaler.joblib'))
        joblib.dump(self.frequency_maps, os.path.join(self.directory_path, 'frequency_maps.joblib'))

    def load_model_and_mappers(self):
        model = joblib.load(os.path.join(self.directory_path, 'lof_model.joblib'))
        scaler = joblib.load(os.path.join(self.directory_path, 'scaler.joblib'))
        self.frequency_maps = joblib.load(os.path.join(self.directory_path, 'frequency_maps.joblib'))
        return model, scaler

    def train(self):
        df_baseline = pd.read_csv(f'baseline_{self.dataset_name}.csv')
        df_baseline = df_baseline.drop_duplicates(self.duplicate_features)
        
        print(f"Training data shape: {df_baseline.shape}")
        
        # Frequency encode
        X_train = self.frequency_encode(df_baseline, fit=True)
        
        # Drop NaN rows
        mask = ~np.isnan(X_train).any(axis=1)
        X_train = X_train[mask]
        
        print(f"Feature matrix shape after encoding: {X_train.shape}")
        print(f"Number of unique values per feature:")
        for col in self.features:
            print(f"  {col}: {df_baseline[col].nunique()}")

        # Scale
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)

        best_params = {'n_neighbors': 20, 'contamination': 0.1}
        lof = self.train_lof(X_train, best_params)

        self.save_model_and_mappers(lof, scaler)
        print(f"Model saved to {self.directory_path}")

    def test(self):
        lof, scaler = self.load_model_and_mappers()

        df_test = pd.read_csv(self.file_name)
        
        if df_test.empty:
            return None, None
        
        df_test = df_test.drop_duplicates(self.duplicate_features)
        
        # Frequency encode
        X_test = self.frequency_encode(df_test, fit=False)
        X_test = scaler.transform(X_test)

        outliers = self.test_lof(lof, X_test)

        df_test['outlier'] = outliers
        detected_outliers = df_test[df_test['outlier'] == -1]

        return detected_outliers, df_test

    def find_descendant(self, process, df_test):
        logs = df_test[df_test['processUUID'] == process]
        descendants = list(logs[logs['event'] == 'fork']['objectUUID'])
        return descendants

    def find_ancestor(self, process, df_test):
        ancestors = list(df_test[df_test['objectUUID'] == process]['processUUID'])
        return ancestors

    def analyze(self):
        if not os.path.exists(self.directory_path):
            self.train()

        detected_outliers, df_test = self.test()
        if detected_outliers is None:
            return None

        anomalous_processes = detected_outliers['processUUID'].unique()
        lineage = []

        for process in anomalous_processes:
            descendants = self.find_descendant(process, df_test)
            ancestor = self.find_ancestor(process, df_test)
            if ancestor:
                lineage.extend(ancestor)
            if descendants:
                lineage.extend(descendants)

        final_anomalous_processes = set(list(anomalous_processes) + lineage)
        df_filtered = df_test[df_test['processUUID'].isin(final_anomalous_processes)]

        return df_filtered