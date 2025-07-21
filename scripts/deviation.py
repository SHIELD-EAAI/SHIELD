import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib
import os

class DeviationAnalyzer:
    def __init__(self, dataset_name, file_name):
        self.dataset_name = dataset_name
        self.file_name = file_name
        self.directory_path = f'model_output_{dataset_name}'
        self.mappers = {
            'process_name_mapper': {},
            'event_mapper': {},
            'object_data_mapper': {},
            'counter': {'processName': 0, 'event': 0, 'objectData': 0}
        }
        self.features = ['event', 'processUUID', 'objectUUID']
        self.duplicate_features = ['event', 'processUUID', 'objectUUID']

    def map_value(self, value, mapper, counter_key):
        if value not in mapper:
            mapper[value] = self.mappers['counter'][counter_key]
            self.mappers['counter'][counter_key] += 1
        return mapper[value]

    def apply_mappings(self, df):
        df['processName'] = df['processName'].map(lambda x: self.map_value(x, self.mappers['process_name_mapper'], 'processName'))
        df['event'] = df['event'].map(lambda x: self.map_value(x, self.mappers['event_mapper'], 'event'))
        df['objectData'] = df['objectData'].map(lambda x: self.map_value(x, self.mappers['object_data_mapper'], 'objectData'))
        return df

    def train_lof(self, X_train, params):
        lof = LocalOutlierFactor(**params)
        lof.fit(X_train)
        return lof

    def test_lof(self, lof, X_test):
        outliers = lof.fit_predict(X_test)
        return outliers

    def save_model_and_mappers(self, model, scaler):
        os.makedirs(self.directory_path, exist_ok=True)
        joblib.dump(model, os.path.join(self.directory_path, 'lof_model.joblib'))
        joblib.dump(scaler, os.path.join(self.directory_path, 'scaler.joblib'))
        joblib.dump(self.mappers, os.path.join(self.directory_path, 'mappers.joblib'))

    def load_model_and_mappers(self):
        model = joblib.load(os.path.join(self.directory_path, 'lof_model.joblib'))
        scaler = joblib.load(os.path.join(self.directory_path, 'scaler.joblib'))
        self.mappers = joblib.load(os.path.join(self.directory_path, 'mappers.joblib'))
        return model, scaler

    def train(self):
        df_baseline = pd.read_csv(f'baseline_{self.dataset_name}.csv')
        df_baseline = df_baseline.drop_duplicates(self.duplicate_features)
        df_baseline = self.apply_mappings(df_baseline)

        X_train = df_baseline[self.features]

        X_train = X_train.dropna()

        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)

        best_params = {'n_neighbors': 20, 'contamination': 0.1, 'novelty': True}
        lof = self.train_lof(X_train, best_params)

        self.save_model_and_mappers(lof, scaler)

    def test(self):
        lof, scaler = self.load_model_and_mappers()

        df_test = pd.read_csv(self.file_name)
        
        if df_test.empty:
            return None, None
        
        df_test = df_test.drop_duplicates(self.duplicate_features)
        df_test = self.apply_mappings(df_test)

        X_test = df_test[self.features]
        
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

        reverse_process_name_mapper = {v: k for k, v in self.mappers['process_name_mapper'].items()}
        reverse_event_mapper = {v: k for k, v in self.mappers['event_mapper'].items()}
        reverse_object_data_mapper = {v: k for k, v in self.mappers['object_data_mapper'].items()}

        detected_outliers['processName'] = detected_outliers['processName'].map(reverse_process_name_mapper)
        detected_outliers['event'] = detected_outliers['event'].map(reverse_event_mapper)
        detected_outliers['objectData'] = detected_outliers['objectData'].map(reverse_object_data_mapper)

        df_test['processName'] = df_test['processName'].map(reverse_process_name_mapper)
        df_test['event'] = df_test['event'].map(reverse_event_mapper)
        df_test['objectData'] = df_test['objectData'].map(reverse_object_data_mapper)

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