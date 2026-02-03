import re
import pickle
import pandas as pd
import networkx as nx
#from pyvis.network import Network

class GraphAnalyzer:
    def __init__(self):
        self.internal_ip_patterns = [
            re.compile(r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})$'),
            re.compile(r'^(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})$'),
            re.compile(r'^(192\.168\.\d{1,3}\.\d{1,3})$'),
            re.compile(r'^(128\.55\.\d{1,3}\.\d{1,3})$'),
            re.compile(r'^(127\.0\.0\.1)$')
        ]
        self.ip_port_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.file_operations = {}
        self.suspicious_files = set()
        self.RG = nx.MultiDiGraph()  # Initialize the streaming graph RG
		
    def analyze(self, df):
        df['dataflow'] = df['event'].apply(self._add_dataflow)
        #df = df[~df['objectData'].str.contains('<unknown>')]
        self._track_file_operations(df)
        self._update_suspicious_files()
        df_suspicious = self._filter_dataframe(df)
        final_df_suspicious = self.get_forks(df, df_suspicious)
        filtered_df = self._create_and_filter_graph(final_df_suspicious, df)
        return filtered_df

    @staticmethod
    def _add_dataflow(event):
        if event in ['read', 'execute', 'receive']:
            return 'inward'
        elif event in ['write', 'modify', 'fork', 'send']:
            return 'outward'
        else:
            return 'unknown'

    def get_forks(self, df, dfs):
        # Step 1: Get all unique processUUIDs
        uuids = dfs['processUUID'].unique()
        df_forked = df[df['event'] == 'fork']
        filtered_records = []
        for _, row in df_forked.iterrows():
            p_uuid = row['processUUID']
            o_uuid = row['objectUUID']
            # Check if both are in uuids
            if p_uuid in uuids and o_uuid in uuids:
                filtered_records.append(row)

        # Convert filtered records back to a DataFrame
        df_filtered = pd.DataFrame(filtered_records, columns=dfs.columns)
        result_df = pd.concat([dfs, df_filtered]).sort_values(by='timestamp')
        return result_df

    def _track_file_operations(self, df):
        file_df = df[df['objectType'].isin(['file', 'process'])]
        
        for _, row in file_df.iterrows():
            file_name = row['objectData']
            if file_name not in self.file_operations:
                self.file_operations[file_name] = []
            
            self.file_operations[file_name].append((row['timestamp'], row['event'], row['processUUID']))

    def _update_suspicious_files(self):
        for file_name, operations in self.file_operations.items():
            sorted_operations = sorted(operations, key=lambda x: x[0])  # Sort by timestamp
            
            if self._has_suspicious_operations(sorted_operations):
                self.suspicious_files.add(file_name)
            
            # Check for inward and outward edges spanning more than 1 process_uuid
            process_uuids = set(op[2] for op in operations)
            inward_processes = set(op[2] for op in operations if op[1] in ['read', 'execute'])
            outward_processes = set(op[2] for op in operations if op[1] in ['write', 'modify', 'fork'])
            
            if len(inward_processes) > 0 and len(outward_processes) > 0 and len(process_uuids) >= 1:
                self.suspicious_files.add(file_name)

    def _has_suspicious_operations(self, operations):
        last_operation = None
        last_process = None
        
        for _, event, process_uuid in operations:
            if event in ['read', 'write', 'execute', 'modify', 'fork']:
                if last_operation:
                    if event != last_operation and process_uuid != last_process:
                        return True
                
                last_operation = event
                last_process = process_uuid
        
        return False

    def _filter_network_comms(self, df):
        suspicious_ips = []
        
        for _, row in df.iterrows():
            match = self.ip_port_pattern.search(row['objectData'])
            if match and self._is_suspicious_ip(match.group()):
                suspicious_ips.append(row)

        return pd.DataFrame(suspicious_ips)

    def _filter_dataframe(self, df):
        suspicious_files_df = df[(df['objectType'].isin(['file', 'process'])) & (df['objectData'].isin(self.suspicious_files))]
        suspicious_df = df[df['objectType'] == 'socket']
        suspicious_network_df = self._filter_network_comms(suspicious_df)

        return pd.concat([suspicious_files_df, suspicious_network_df]).sort_values(by='timestamp')

    def _is_suspicious_ip(self, ip):
        return not any(pattern.match(ip) for pattern in self.internal_ip_patterns)
    
    @staticmethod
    def _has_send_or_receive_event(subgraph):
        return any("send" in data['label'].lower() or "receive" in data['label'].lower() 
                   for _, _, data in subgraph.edges(data=True))

    def _create_and_filter_graph(self, df_suspicious, original_df):
        G = nx.MultiDiGraph()

        # Add nodes and edges to the graph
        for index, row in df_suspicious.iterrows():
            process_uuid = row['processUUID']
            object_uuid = row['objectUUID']
            process_name = row['processName']
            object_data = row['objectData']
            event = row['event']
            dataflow = row['dataflow']
            timestamp = row['timestamp']
            object_type = row['objectType']

            # Skip rows with NaN values in critical fields
            if pd.isna(process_uuid) or pd.isna(object_uuid) or pd.isna(process_name) or pd.isna(object_data):
                continue
            
            if object_data in ['/dev/pts/2', '<unknown>', '.bash_history']:
                continue
            
            if object_type == 'file' and object_data in self.suspicious_files:
                is_imp = 'yes'
            elif object_type == 'socket':
                is_imp = 'yes'
            else:
                is_imp = 'no'

            # Add nodes with appropriate labels
            G.add_node(process_uuid, label=process_name, node_type='process', tagged_node='no', probability=0.0)
            G.add_node(object_uuid, label=object_data, node_type='object', tagged_node='no', probability=0.0, important=is_imp)

            # Add edges based on dataflow direction
            if dataflow == 'inward':
                G.add_edge(object_uuid, process_uuid, key=event, label=event, time=timestamp)
            elif dataflow == 'outward':
                G.add_edge(process_uuid, object_uuid, key=event, label=event, time=timestamp)

        # Find all connected components (subgraphs)
        subgraphs = [G.subgraph(c).copy() for c in nx.weakly_connected_components(G)]

        # Filter out subgraphs without 'send' or 'receive' events
        subgraphs_to_keep = [subgraph for subgraph in subgraphs if self._has_send_or_receive_event(subgraph)]

        # Combine the kept subgraphs into a new graph
        H = nx.MultiDiGraph()
        for subgraph in subgraphs_to_keep:
            H = nx.compose(H, subgraph)

        # Add H to RG without redundancy
        self._add_to_streaming_graph(H)

        nodes_in_H = set(H.nodes())
        filtered_df = df_suspicious[df_suspicious['processUUID'].isin(nodes_in_H) | df_suspicious['objectUUID'].isin(nodes_in_H)]

        return filtered_df

    
    def _add_to_streaming_graph(self, subgraph):
        for node, data in subgraph.nodes(data=True):
            if not self.RG.has_node(node):
                self.RG.add_node(node, **data)

        for u, v, key, data in subgraph.edges(data=True, keys=True):
            if not self.RG.has_edge(u, v, key=key):
                self.RG.add_edge(u, v, key=key, **data)
	
    def save_graph(self, graph, filename):
        with open(filename, 'wb') as f:
            pickle.dump(graph, f, pickle.HIGHEST_PROTOCOL)

    def perform_post_processing(self):
        important_nodes = [node for node, data in self.RG.nodes(data=True) if data.get('important') == 'yes']
        ni_nodes = []
        for node in important_nodes:
            in_degree = self.RG.in_degree(node)
            out_degree = self.RG.out_degree(node)
            
            if in_degree == 0 or out_degree == 0:
                ni_nodes.append(node)

        # Print the number of nodes before any removal
        print(f"Number of nodes before removal: {self.RG.number_of_nodes()}")

        # Remove the ni_nodes from the graph
        self.RG.remove_nodes_from(ni_nodes)

        # Get isolated nodes
        isolated_nodes = list(nx.isolates(self.RG))

        # Remove isolated nodes
        self.RG.remove_nodes_from(isolated_nodes)

        # Print the number of nodes after removal
        print(f"Number of nodes after removal: {self.RG.number_of_nodes()}")

    def finalize_analysis(self):
        result = self.suspicious_files.copy()
        result2 = self.file_operations.copy()
        self.file_operations.clear()
        self.suspicious_files.clear()

        graph_file = "provenance_graph.gpickle"
        self.perform_post_processing()
        self.save_graph(self.RG, graph_file)
        

        print(f"No of nodes in the graph after the file {graph_file} was added: {self.RG.number_of_nodes()}")
        self.RG.clear()

        return result, result2