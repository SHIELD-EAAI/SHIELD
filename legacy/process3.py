import os
import re
import numpy as np
import pandas as pd
import networkx as nx
import community as community_louvain
from datetime import datetime, date
import pickle
from collections import defaultdict
from pyvis.network import Network # type: ignore
import logging
import statistics
import json

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='graph_processor.log',
    filemode='w'
)
logger = logging.getLogger(__name__)

class GraphProcessor:
    def __init__(self, llm_analyzer):
        self.RG = None
        self.grouper = UUIDGrouper()
        self.files_analyzed = 0
        self.llm_analyzer = llm_analyzer
        self.attack_sets = {}  # Persistent storage for attack sets
        self.next_set_id = 0   # Counter for assigning new set IDs
        self.object_to_set_mapping = defaultdict(set)
        self.process_to_set_mapping = defaultdict(set)
        self.set_probability = defaultdict(float)
        self.set_count = defaultdict(int)

    def load_reduced_graph(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                self.RG = pickle.load(f)
            print(f"Loaded graph with {len(self.RG.nodes())} nodes")
        else:
            print(f"Graph file {filename} not found")
            self.RG = nx.MultiDiGraph()

    def save_graph(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self.RG, f)
        print(f"Updated graph saved as {filename}")

    def count_tagged_nodes(self):
        return sum(1 for _, data in self.RG.nodes(data=True) if data.get('tagged_node') == 'yes')

    def print_tagging_stats(self):
        total_nodes = len(self.RG.nodes())
        tagged_nodes = self.count_tagged_nodes()
        untagged_nodes = total_nodes - tagged_nodes
        tagged_percentage = (tagged_nodes / total_nodes) * 100 if total_nodes > 0 else 0

        print(f"Total nodes: {total_nodes}")
        print(f"Tagged nodes: {tagged_nodes}")
        print(f"Untagged nodes: {untagged_nodes}")
        print(f"Percentage of tagged nodes: {tagged_percentage:.2f}%")

    def tag_reachable_nodes(self, start_node, value):
        reachable_nodes = set(nx.single_source_shortest_path_length(self.RG, start_node).keys())
        for node in reachable_nodes:
            if self.RG.nodes[node].get('tagged_node') != 'yes':
                self.RG.nodes[node]['tagged_node'] = 'yes'
            if self.RG.nodes[node].get('probability') < value:   
                self.RG.nodes[node]['probability'] = value

    def remove_untagged_nodes(self):
        nodes_to_remove = [node for node, data in self.RG.nodes(data=True) if data.get('tagged_node') != 'yes']
        self.RG.remove_nodes_from(nodes_to_remove)
        print(f"Removed {len(nodes_to_remove)} untagged nodes")
        print(f"Graph now has {len(self.RG.nodes())} nodes")

    def get_uuid_from_number(self, number, number_to_uuid):
        return number_to_uuid.get(number, None)
    def extract_ip_ports(self, nodes):
        if not nodes:
            return []
        
        ip_port_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b')
        ip_ports = []
        
        for node in nodes:
            try:
                if isinstance(node, str):
                    match = ip_port_pattern.search(node)
                    if match:
                        ip_ports.append(match.group())
            except Exception:
                continue
        
        return list(set(ip_ports))
    
    def get_suspicious_logs(self, df, nodes, number_to_uuid):
        procs = []
        for node in nodes:
            try:
                if '#' in node:
                    uuid_number = int(node.split('#')[1])
                    uuid = self.get_uuid_from_number(uuid_number, number_to_uuid)
                    if uuid:
                        procs.append(uuid)
                    else:
                        print(f"Could not map UUID {uuid_number}. Logic Error")
            except Exception as e:
                print(node)

        logs_df = df[df['processUUID'].isin(procs)]
        return logs_df

    def extract_processes(self, nodes):
        processes = []
        for node in nodes:
            try:
                if node is not None and "#" in str(node):
                    processes.append(str(node))
            except Exception:
                continue
        return processes

    def preprocess_file_data(self, G, df):
        try:
            df = df.dropna(subset=['processName', 'processUUID'])
            most_frequent_names = df.groupby('processUUID')['processName'].agg(lambda x: x.value_counts().idxmax()).reset_index()
            df = df.merge(most_frequent_names, on='processUUID', suffixes=('', '_most_frequent'))
            
            unique_combinations = df.drop_duplicates(subset=['processName_most_frequent', 'processUUID'])
            combination_mapping = {(row['processName_most_frequent'], row['processUUID']): idx + 1 for idx, row in unique_combinations.iterrows()}
            
            uuid_to_number = {row['processUUID']: idx + 1 for idx, row in unique_combinations.iterrows()}
            number_to_uuid = {number: uuid for uuid, number in uuid_to_number.items()}

            df['process_name#process_uuid'] = df.apply(lambda row: f"{row['processName_most_frequent']}#{combination_mapping[(row['processName_most_frequent'], row['processUUID'])]}", axis=1)
            
            unique_processes = df['process_name#process_uuid'].unique()
            unique_objects = df['objectData'].unique()
            
            for process in unique_processes:
                G.add_node(process)
            for obj in unique_objects:
                G.add_node(obj)

            for _, row in df.iterrows():
                if row['dataflow'] == 'outward':
                    G.add_edge(row['process_name#process_uuid'], row['objectData'])
                elif row['dataflow'] == 'inward':
                    G.add_edge(row['objectData'], row['process_name#process_uuid'])
            
            return number_to_uuid
        except Exception as e:
            print(f"Error in preprocess_file_data: {e}")
            return None

    def find_communities(self, G):
        undirected_G = G.to_undirected()
        suspicious_nodes = []
        
        partition = community_louvain.best_partition(undirected_G)
        
        community_dict = {}
        for node, community in partition.items():
            if community not in community_dict:
                community_dict[community] = []
            community_dict[community].append(node)
        
        for community, nodes in community_dict.items():
            extracted_ip_ports = self.extract_ip_ports(nodes)
            extracted_processes = self.extract_processes(nodes)
            if extracted_ip_ports and len(extracted_processes) >= 2:
                suspicious_nodes.append(nodes)
        
        return suspicious_nodes

    def convert_timestamps(self, logs):
        fmt = '%Y-%m-%d %H:%M:%S.%f'
        start_time_str = logs[0].split(',')[-1].strip()[:-3]
        start_time = datetime.strptime(start_time_str, fmt)
        new_logs = []

        for log in logs:
            parts = log.split(',')
            timestamp_str = parts[-1].strip()[:-3]
            timestamp = datetime.strptime(timestamp_str, fmt)
            elapsed_time = timestamp - start_time
            elapsed_seconds = elapsed_time.total_seconds()
            elapsed_formatted = "{:02}:{:02}:{:06.3f}".format(
                int(elapsed_seconds // 3600),
                int((elapsed_seconds % 3600) // 60),
                elapsed_seconds % 60
            )
            new_log = ','.join(parts[:-1]) + ',' + elapsed_formatted
            new_logs.append(new_log)

        return new_logs

    def save_logs_to_file(self, logs, file_path):
        try:
            uuid_cols = ['processUUID', 'objectUUID']
            uuid_mappings = {}
            for col in uuid_cols:
                unique_ids = {id_: idx for idx, id_ in enumerate(logs[col].unique())}
                logs[col] = logs[col].map(unique_ids)
                if col == 'processUUID':
                    uuid_mappings = {idx: id_ for id_, idx in unique_ids.items()}
            
            logs = logs.drop(columns=['objectType'])
            logs.loc[:, 'dataflow'] = logs['dataflow'].replace({'inward': 'in', 'outward': 'out'})

            logs = logs.sort_values(by=['timestamp'])
            logs = logs[['processUUID', 'processName', 'event', 'objectUUID', 'objectData', 'dataflow', 'timestamp']]

            if logs.empty:
                return None, {}

            data_string = logs.apply(lambda x: ','.join(x.astype(str)), axis=1).str.cat(sep=';')
            log_string = data_string.split(';')[:-1]
            final_data = self.convert_timestamps(log_string)
            data_string = ';'.join(final_data) + ';'
        except Exception as e:
            print(e)

        return data_string, uuid_mappings

    def process_file(self, file_path):
        df = pd.read_csv(file_path)
        if not df.empty:
            G = nx.DiGraph()
            number_to_uuid = self.preprocess_file_data(G, df)
            if number_to_uuid is None:
                print(f"Error preprocessing file: {file_path}")
                return
            print(f"Response for file: {os.path.basename(file_path)}")
            suspicious_nodes = self.find_communities(G)
            for community in suspicious_nodes:
                logs = self.get_suspicious_logs(df, community, number_to_uuid)
                data_string, mapping = self.save_logs_to_file(logs, file_path)
                if data_string is None:
                    print(f"No valid logs found in file: {file_path}")
                    continue
                final_processes, result = self.llm_analyzer.main(data_string)
                
                if final_processes and float(result['analysis_probability'] >= 0.80):
                    try:
                        print(f" Got the results:  {final_processes}")
                        coherent = self.llm_analyzer.process_get_final_conclusion(data_string, final_processes)
                        coherent = json.loads(coherent)
                        value = float(coherent['probability_score'])
                        print(f"Probability_Score: {value}")
                        if value >= 0.8:
                            print(f"Final Result found: {result}")

                        process_ids = coherent['process_uuids']
                        process_uuids = [mapping[int(key)] for key in process_ids]
                        print(process_uuids)
                        self.grouper.process_new_list(process_uuids, value)
                        
                        for process_uuid in process_uuids:
                            if process_uuid in self.RG.nodes():
                                self.tag_reachable_nodes(process_uuid, value)
                            else:
                                print(f"Process UUID {process_uuid} not found in the reduced graph")
                    except KeyError as e:
                        print(f"KeyError encountered: {e}")
        
        self.files_analyzed += 1
        if self.files_analyzed % 9 == 0:
            self.save_graph("provenance_graph.gpickle")

    def get_node_info(self):
        return self.grouper.get_node_info(self.RG)

    def filter_nodes_by_type(self, nodes):
        filtered_nodes = []
        for node in nodes:
            node_data = self.RG.nodes[node]
            node_type = node_data.get('node_type')
            
            if node_type == 'object':
                if node_data.get('important') == 'yes':
                    filtered_nodes.append(node)
            else:
                filtered_nodes.append(node)
        
        return filtered_nodes

    def analyze_directory(self, directory_path):
        pattern = r'processed_file_sliding_window_from_(\d{4}-\d{2}-\d{2})-01-00_to_\1-01-30'
        current_date = None

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                match = re.match(pattern, file)
                if match:
                    file_date = datetime.strptime(match.group(1), '%Y-%m-%d').date()
                    
                    if file_date != current_date:
                        self.perform_day_start_action(file_date)
                        current_date = file_date
                        
                file_path = os.path.join(root, file)
                self.process_file(file_path)
                results = self.analyze() 
                if results is not None:
                    for result in results:   
                        print(f"Set {result['set_id']} changed:")
                        print(f"Description: {result['description']}")
                        print(f"Set data: {result['set_data']}")
                        #print(json.dumps(result['set_data'], indent=2))
                        print("---"

    def perform_day_start_action(self, input_date):
        print(f"Performing action for the start of day: {input_date}")

        if isinstance(input_date, str):
            input_date = datetime.strptime(input_date, '%Y-%m-%d').date()
        elif isinstance(input_date, datetime):
            input_date = input_date.date()
        elif not isinstance(input_date, date):
            raise ValueError("Invalid date format. Expected string, datetime, or date object.")

        edges_to_remove = []
        for u, v, key, data in self.RG.edges(data=True, keys=True):
            edge_time = data.get('time')
            edge_date = self.extract_date(edge_time)

            if edge_date and isinstance(edge_date, date) and edge_date < input_date:
                edges_to_remove.append((u, v, key))

        self.RG.remove_edges_from(edges_to_remove)

        isolated_nodes = list(nx.isolates(self.RG))
        self.RG.remove_nodes_from(isolated_nodes)

        print(f"Removed {len(edges_to_remove)} edges and {len(isolated_nodes)} isolated nodes")

        self.save_graph("provenance_graph.gpickle")
         

    def extract_date(self, timestamp):
        if timestamp == 'None' or timestamp is None:
            return None
        try:
            return datetime.strptime(timestamp[:10], '%Y-%m-%d').date()
        except ValueError:
            return None
    
    def get_tagged_nodes(self):
        return [node for node, data in self.RG.nodes(data=True) if data.get('tagged_node') == 'yes']

    def analyze(self):
        results = self.grouper.get_groups(self.RG)
        if not results:
            return None

        result_sets = self.trace_and_group_sets(results)
        
        current_sets = self.get_sorted_sets_with_node_info(result_sets)

        changed_sets = {}
        for current_set in current_sets:
            
            set_id = self.find_or_create_set(current_set)
            if self.is_set_changed(set_id, current_set):
                changed_sets[set_id] = self.merge_with_existing_set(set_id, current_set)
                self.update_attack_set(set_id, changed_sets[set_id])
        
        if not changed_sets:
            return None
        
        self.merge_related_sets()
        
        def sort_key(tup):
            timestamp = tup[3]
            if timestamp == 'None':
                return datetime.max
            try:
                return datetime.strptime(timestamp[:26], '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                return datetime.max

        final_results = []
        for set_id, changed_set in changed_sets.items():
            if self.set_probability[set_id] < 0.7:
                continue
            sorted_set = sorted(changed_set, key=sort_key)
            result = self.llm_analyzer.process_get_result_from_llm(sorted_set)
            if result["is_coherent_attack"] and result["probability_score"] >= 0.7:
                final_results.append({
                    "set_id": set_id,
                    "description": result["description"],
                    "set_data": sorted_set,
                })
        
        return final_results if final_results else None

    def find_or_create_set(self, current_set):
        for event in current_set:
            _, _, obj, _, _ = event
            related_sets = self.object_to_set_mapping.get(obj, set())
            if related_sets:
                return min(related_sets)
        
        new_set_id = self.next_set_id
        self.next_set_id += 1
        return new_set_id

    def is_set_changed(self, set_id, current_set):
        if set_id not in self.attack_sets:
            return True
        existing_set = self.attack_sets[set_id]
        return any(event not in existing_set for event in current_set)

    def merge_with_existing_set(self, set_id, current_set):
        if set_id not in self.attack_sets:
            return current_set
        existing_set = self.attack_sets[set_id]
        merged_set = existing_set[:]  # Create a copy of the existing set
        for event in current_set:
            if event not in merged_set:
                merged_set.append(event)
        return merged_set

    def update_attack_set(self, set_id, new_set):
        self.attack_sets[set_id] = new_set
        self.update_mappings(set_id, new_set)

    def update_mappings(self, set_id, events):
        for event in events:
            process, _, obj, _, _ = event
            self.object_to_set_mapping[obj].add(set_id)

    def merge_related_sets(self):
        merged = True
        while merged:
            merged = False
            sets_to_merge = defaultdict(set)
            
            for mappings in [self.object_to_set_mapping, self.process_to_set_mapping]:
                for _, set_ids in mappings.items():
                    if len(set_ids) > 1:
                        target_set_id = min(set_ids)
                        sets_to_merge[target_set_id].update(set_ids)

            for target_set_id, merge_set_ids in sets_to_merge.items():
                if len(merge_set_ids) > 1:
                    merged = True
                    all_events = []
                    for set_id in merge_set_ids:
                        all_events.extend(self.attack_sets[set_id])
                        if set_id != target_set_id:
                            del self.attack_sets[set_id]
                    
                    self.attack_sets[target_set_id] = all_events
                    
                    for mapping in [self.object_to_set_mapping, self.process_to_set_mapping]:
                        for key, set_ids in list(mapping.items()):
                            if set_ids & merge_set_ids:
                                mapping[key] = {target_set_id}


    def print_sets(self, threshold=0.80):
        for set_id, events in self.attack_sets.items():
            probability = self.set_probability.get(set_id, 0.0)
            if probability == 0.0 and events:
                try:
                    probability = min(float(event[4]) for event in events if event[4] != 'None')
                except (ValueError, TypeError):
                    probability = 0.0
            if probability >= threshold:
                print(f"Set {set_id}:")
                sorted_events = sorted(events, key=lambda x: datetime.max if x[3] == 'None' else datetime.strptime(x[3][:26], '%Y-%m-%d %H:%M:%S.%f'))
                for event in sorted_events:
                    print(f"  {event}")
                print()
	
    def trace_and_group_sets(self, initial_sets):

        all_nodes = set.union(*initial_sets)
        
        missing_nodes = all_nodes - set(self.RG.nodes())
        if missing_nodes:
            logger.warning(f"Found {len(missing_nodes)} nodes in initial_sets that are not in RG: {missing_nodes}")
        
        new_sets = []
        processed_nodes = set()

        while all_nodes:
            current_node = all_nodes.pop()

            if current_node in processed_nodes:
                continue

            if current_node not in self.RG:
                continue

            try:
                reachable_nodes = set(nx.single_source_shortest_path_length(self.RG, current_node).keys())
            except nx.NodeNotFound:
                continue

            filtered_nodes = set(self.filter_nodes_by_type(reachable_nodes))
            
            existing_set = next((s for s in new_sets if s & filtered_nodes), None)

            if existing_set:
                existing_set.add(current_node)
                existing_set.update(filtered_nodes & all_nodes)
                single_element_sets = [s for s in new_sets if len(s) == 1 and s.issubset(filtered_nodes)]
                for single_set in single_element_sets:
                    existing_set.update(single_set)
                    new_sets.remove(single_set)
            else:
                new_set = (filtered_nodes & all_nodes) | {current_node}
                new_sets.append(new_set)

            processed_nodes.update(filtered_nodes & all_nodes)
            processed_nodes.add(current_node)
            all_nodes -= processed_nodes
            
        return new_sets


    def get_sorted_sets_with_node_info(self, result_sets):
        sorted_sets = []
        for i, result_set in enumerate(result_sets, 1):
            if len(result_set) <= 1:
                continue

            unique_tuples = set()
            for node in result_set:
                outgoing_edges = self.RG.out_edges(node, keys=True, data=True)
                incoming_edges = self.RG.in_edges(node, keys=True, data=True)

                for edge in outgoing_edges:
                    unique_tuples.add((self.RG.nodes[edge[0]].get('label', 'Unknown'), edge[2], self.RG.nodes[edge[1]].get('label', 'Unknown'), edge[3].get('time', 'None'), self.RG.nodes[node].get('probability', 'None')))

                for edge in incoming_edges:
                    unique_tuples.add((self.RG.nodes[edge[1]].get('label', 'Unknown'), edge[2], self.RG.nodes[edge[0]].get('label', 'Unknown'), edge[3].get('time', 'None'), self.RG.nodes[node].get('probability', 'None')))

            grouped_tuples = defaultdict(list)
            for tup in unique_tuples:
                key = tup[:3]
                grouped_tuples[key].append(tup)

            final_tuples = []
            for group in grouped_tuples.values():
                earliest_tuple = min(group, key=lambda x: x[3] if x[3] != 'None' else float('inf'))
                final_tuples.append(earliest_tuple)

            def sort_key(tup):
                timestamp = tup[3]
                if timestamp == 'None':
                    return datetime.max
                try:
                    return datetime.strptime(timestamp[:26], '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    return datetime.max

            sorted_tuples = sorted(final_tuples, key=sort_key)
            sorted_sets.append(sorted_tuples)

        return sorted_sets
    
    def finalize(self):
        print("Finalizing analysis...")

        self.print_sets()

        self.remove_untagged_nodes()
        self.save_graph("provenance_graph.gpickle")

        net = Network(notebook=False, cdn_resources='remote')
        net.from_nx(self.RG)
        net.save_graph("graph_visualization.html")

class UUIDGrouper:
    def __init__(self):
        self.uuid_sets = []
        self.set_probabilities = []

    def process_new_list(self, uuid_list, probability_value):
        new_set = set(uuid_list)
        matched_indices = []
        
        for i, existing_set in enumerate(self.uuid_sets):
            if existing_set.intersection(new_set):
                matched_indices.append(i)
        
        if matched_indices:
            merged_set = set.union(new_set, *[self.uuid_sets[i] for i in matched_indices])
            
            max_probability = max([probability_value] + [self.set_probabilities[i] for i in matched_indices])
            
            for i in sorted(matched_indices, reverse=True):
                del self.uuid_sets[i]
                del self.set_probabilities[i]
            
            self.uuid_sets.append(merged_set)
            self.set_probabilities.append(max_probability)
        else:
            self.uuid_sets.append(new_set)
            self.set_probabilities.append(probability_value)

    def synchronize_with_graph(self, graph):
        """Remove nodes that are no longer in the graph."""
        nodes_in_graph = set(graph.nodes())
        removed_nodes = set()
        for i, uuid_set in enumerate(self.uuid_sets):
            nodes_to_remove = uuid_set - nodes_in_graph
            uuid_set.difference_update(nodes_to_remove)
            removed_nodes.update(nodes_to_remove)
        
        self.uuid_sets = [s for s in self.uuid_sets if s]
        self.set_probabilities = [p for s, p in zip(self.uuid_sets, self.set_probabilities) if s]
        
        if removed_nodes:
            logger.info(f"Removed {len(removed_nodes)} nodes from UUIDGrouper that are no longer in the graph.")
        return removed_nodes

    def get_groups(self, graph):
        """
        Return the sets with nodes that exist in the current graph, 
        along with their probabilities, filtered by a probability threshold.
        """
        self.synchronize_with_graph(graph)
        groups = []
        
        for uuid_set, probability in zip(self.uuid_sets, self.set_probabilities):
            if uuid_set:
                groups.append(uuid_set)

        return groups

    def get_node_info(self, graph):
        node_info = []
        for i, (uuid_set, probability) in enumerate(zip(self.uuid_sets, self.set_probabilities), 1):
            set_info = {f"Set {i}": []}
            for uuid in uuid_set:
                if uuid in graph.nodes:
                    node_data = graph.nodes[uuid].copy()
                    node_data['probability'] = probability
                    set_info[f"Set {i}"].append({uuid: node_data})
                else:
                    set_info[f"Set {i}"].append({uuid: {"info": "Node not found in graph", "probability": probability}})
            node_info.append(set_info)
        return node_info