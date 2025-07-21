import os
import pandas as pd
from datetime import datetime, timedelta

class DatasetCreation:
    def __init__(self, dataset, dataset_file, lower_bound, upper_bound, interval, sliding_window):
        self.dataset = dataset
        self.create_directory_if_not_exists()
        self.df = pd.read_pickle(dataset_file)
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.interval = timedelta(minutes=interval)
        self.sliding_window = timedelta(minutes=sliding_window)

    def create_directory_if_not_exists(self):
        if not os.path.exists(self.dataset):
            os.makedirs(self.dataset)

    def create_dataset(self):
        start_time = datetime.strptime(self.lower_bound, "%Y-%m-%d %H:%M")
        end_time = datetime.strptime(self.upper_bound, "%Y-%m-%d %H:%M")
        counter = 1
        current_start = start_time
        intervals = []

        while current_start + self.interval <= end_time:
            current_end = current_start + self.interval
            intervals.append((
                current_start.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + '000000',
                current_end.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + '000000'
            ))
            #current_start += self.interval
            current_start += self.sliding_window

        for interval in intervals:
            start_time = interval[0]
            end_time = interval[1]
            start_time_date = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f000000').strftime('%Y-%m-%d-%H-%M')
            end_time_date = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S.%f000000').strftime('%Y-%m-%d-%H-%M')
            filtered_df = self.df[(self.df['timestamp'] >= start_time) & (self.df['timestamp'] <= end_time)]
            file_name = f'{self.dataset}/file_sliding_window_from_{start_time_date}_to_{end_time_date}.csv'
            filtered_df.to_csv(file_name, index=False)
            filtered_df = filtered_df.drop(filtered_df.index)
            counter += 1