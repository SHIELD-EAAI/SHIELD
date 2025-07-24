import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.neighbors import LocalOutlierFactor
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, TransformerMixin
import joblib
import os
import hashlib

class DeviationAnalyzer:
    def __init__(self, dataset_name, file_name):
        self.dataset_name = dataset_name
        self.file_name = file_name
        self.directory_path = f'model_output_{dataset_name}'
        self.features = ['event', 'processUUID', 'objectUUID']
        self.duplicate_features = ['event', 'processUUID', 'objectUUID']
        self.preprocessor = None
        self.model = None
        self.config = {
            'uuid_hash_length': 8,
            'max_categories': 50,
            'contamination': 0.1,
            'lof_neighbors': 20
        }
        self.encoders = {}
        
    def _hash_uuid(self, uuid_str):
        if pd.isna(uuid_str) or uuid_str == '' or uuid_str is None:
            return 'missing'
        return hashlib.md5(str(uuid_str).encode()).hexdigest()[:self.config['uuid_hash_length']]
    
    def _create_preprocessor(self, df):
        transformers = []
        
        categorical_features = ['event', 'processName', 'objectData']
        uuid_features = ['processUUID', 'objectUUID']
        
        for feature in categorical_features:
            if feature in df.columns:
                n_unique = df[feature].nunique()
                if n_unique <= self.config['max_categories']:
                    transformers.append(('onehot_' + feature, OneHotEncoder(drop='first', sparse_output=False, handle_unknown='ignore'), [feature]))
                else:
                    transformers.append(('passthrough_' + feature, 'passthrough', [feature]))
        
        uuid_present = [f for f in uuid_features if f in df.columns]
        for uuid_col in uuid_present:
            transformers.append(('passthrough_' + uuid_col, 'passthrough', [uuid_col]))
                    
        return ColumnTransformer(transformers=transformers, remainder='drop')
    
    def _manual_encode_features(self, df, fit_encoders=True):
        df_encoded = df.copy()
        
        categorical_features = ['event', 'processName', 'objectData']
        uuid_features = ['processUUID', 'objectUUID']
        
        for feature in categorical_features:
            if feature in df.columns:
                n_unique = df[feature].nunique()
                if n_unique > self.config['max_categories']:
                    if fit_encoders:
                        encoder = LabelEncoder()
                        df_encoded[feature] = encoder.fit_transform(df_encoded[feature].astype(str))
                        self.encoders[feature] = encoder
                    else:
                        encoder = self.encoders[feature]
                        known_classes = set(encoder.classes_)
                        df_encoded[feature] = df_encoded[feature].astype(str)
                        df_encoded[feature] = df_encoded[feature].apply(
                            lambda x: x if x in known_classes else 'unknown'
                        )
                        if 'unknown' not in known_classes:
                            encoder.classes_ = np.append(encoder.classes_, 'unknown')
                        df_encoded[feature] = encoder.transform(df_encoded[feature])
        
        for uuid_col in uuid_features:
            if uuid_col in df.columns:
                df_encoded[uuid_col] = df_encoded[uuid_col].apply(self._hash_uuid)
                
                if fit_encoders:
                    encoder = LabelEncoder()
                    df_encoded[uuid_col] = encoder.fit_transform(df_encoded[uuid_col].astype(str))
                    self.encoders[uuid_col] = encoder
                else:
                    encoder = self.encoders[uuid_col]
                    known_classes = set(encoder.classes_)
                    df_encoded[uuid_col] = df_encoded[uuid_col].astype(str)
                    df_encoded[uuid_col] = df_encoded[uuid_col].apply(
                        lambda x: x if x in known_classes else 'unknown'
                    )
                    if 'unknown' not in known_classes:
                        encoder.classes_ = np.append(encoder.classes_, 'unknown')
                    df_encoded[uuid_col] = encoder.transform(df_encoded[uuid_col])
        
        return df_encoded
    
    def _prepare_data(self, df, fit_preprocessor=True):
        df = df.copy()
        
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].fillna('missing')
            else:
                df[col] = df[col].fillna(df[col].median())
        
        df = df.drop_duplicates(self.duplicate_features)
        
        df_encoded = self._manual_encode_features(df, fit_encoders=fit_preprocessor)
        
        if fit_preprocessor:
            self.preprocessor = self._create_preprocessor(df_encoded)
            X = self.preprocessor.fit_transform(df_encoded)
        else:
            X = self.preprocessor.transform(df_encoded)
        
        return X
    
    def train_lof(self, X_train, params):
        lof = LocalOutlierFactor(**params)
        lof.fit(X_train)
        return lof
    
    def test_lof(self, lof, X_test):
        outliers = lof.predict(X_test)
        return outliers
    
    def save_model_and_mappers(self, model, scaler):
        os.makedirs(self.directory_path, exist_ok=True)
        joblib.dump(model, os.path.join(self.directory_path, 'lof_model.joblib'))
        joblib.dump(scaler, os.path.join(self.directory_path, 'scaler.joblib'))
        joblib.dump(self.preprocessor, os.path.join(self.directory_path, 'preprocessor.joblib'))
        joblib.dump(self.encoders, os.path.join(self.directory_path, 'encoders.joblib'))
    
    def load_model_and_mappers(self):
        model = joblib.load(os.path.join(self.directory_path, 'lof_model.joblib'))
        scaler = joblib.load(os.path.join(self.directory_path, 'scaler.joblib'))
        self.preprocessor = joblib.load(os.path.join(self.directory_path, 'preprocessor.joblib'))
        self.encoders = joblib.load(os.path.join(self.directory_path, 'encoders.joblib'))
        return model, scaler
    
    def train(self):
        df_baseline = pd.read_csv(f'baseline_{self.dataset_name}.csv')
        X_train = self._prepare_data(df_baseline, fit_preprocessor=True)
        
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        
        n_neighbors = min(self.config['lof_neighbors'], len(X_train) - 1)
        best_params = {'n_neighbors': n_neighbors, 'contamination': self.config['contamination'], 'novelty': True}
        lof = self.train_lof(X_train, best_params)
        
        self.save_model_and_mappers(lof, scaler)
    
    def test(self):
        lof, scaler = self.load_model_and_mappers()
        df_test = pd.read_csv(self.file_name)
        
        if df_test.empty:
            return None, None
        
        X_test = self._prepare_data(df_test, fit_preprocessor=False)
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