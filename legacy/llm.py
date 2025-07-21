import json
import threading


class LLMAnalyzer:
    def __init__(self, client, deployment):
        self.client = client
        self.deployment = deployment

    def get_response_from_llm(self, data_string):
        context = "You are a security analyst tasked with identifying suspicious processes from a set of event logs. The event logs will be provided in the input, and your job is to analyze them and identify any processes involved in a potential attack. Please output the response in a JSON format, listing the process names that are part of the attack"
        
        guidelines = """Format of System level Logs: Each record in the event logs is separated by semicolons, and fields within records are separated by commas. The fields are: - 'processUUID': Unique ID for the process - 'processName': Name of the process - 'event': Type of operation performed (read, write, execute, modify, send, receive, fork) - 'objectUUID': Unique ID for the object - 'objectData': Details of the object on which the operation was performed - 'dataflow': 'in' indicates data coming into the process, 'out' indicates the process sending data - 'timestamp': Time from the start of the logs captured in minutes. Analyze the provided event logs to determine if there are any true positive security alerts indicating potential security incidents. If true positive alerts are found, list the processes involved in the suspicious activities. If no true positive alerts are found, indicate that the files and activities are benign by returning an empty Python list.

        Output Format Example
        {
        "attack_processes": ['svchost.exe', 'winexplorer.exe']
        }
        """

        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}"
        }

        initial_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )

        return initial_response.choices[0].message.content.strip()

    
    def get_validation_from_llm(self, data_string, output):
        context = "As a security analyst, your task is to validate the accuracy of MITRE TTPs mapping identified by an LLM from analysis of a L1 engineer. You will be provided with the analysis and the mappings. Your task is to analyze the the MITRE Tactics and Techniques mapped to the activities performed during an attack and determine if the identified mappings are correct, if not modify them accordingly. If no changes are necessary, return the original mapping. Please output your findings in JSON format."
        
        guidelines = """

        Output Format Example
        {
        "attack_processes": ['svchost.exe', 'winexplorer.exe']
        }
        """

        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nIdentified suspicious processes:{output}"
        }

        validation_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )

        return validation_response.choices[0].message.content.strip()

        
    def main(self, data_string):
        output = list()
        final_output = list()
        try:
            result = json.loads(self.get_response_from_llm(data_string))
        except Exception as e:
            print(e)

        if "attack_processes" in result:
            output = result["attack_processes"]

        try:
            validation = json.loads(self.get_validation_from_llm(data_string, output))
        except Exception as e:
            print(e)
        
        if "attack_processes" in validation:
            final_output = validation["attack_processes"]

        return final_output

    def get_final_conclusion(self, data_string, final_processes):
        context = ("You are a security analyst tasked with validating potential attack processes from a set of event logs. "
                   "The event logs and the identified attack processes will be provided as input. Your job is to analyze the logs related to these processes and determine whether they form a coherent attack."
                   "If they do, please provide a brief explanation of the attack in natural language. If they do not form a coherent attack, indicate that the processes are suspicious but do not form a coherent attack. 'is_coherent_attack': 'No'"
                   "Provide the response in json format")

        guidelines = ("""
        Guidelines: Each record in the event logs is separated by semicolons, and fields within records are separated by commas. The fields are:

        - 'processUUID': Unique ID for the process
        - 'processName': Name of the process
        - 'event': Type of operation performed (read, write, execute, modify, send, receive, fork)
        - 'objectUUID': Unique ID for the object
        - 'objectData': Details of the object on which the operation was performed
        - 'dataflow': 'in' indicates data coming into the process, 'out' indicates the process sending data
        - 'timestamp': Time from the start of the logs captured in minutes

        Please use the following input format to provide your analysis:

        Input:
        {
            "event_logs": "log1;log2;log3;...",
            "attack_processes": ["process1", "process2"]
        }

        Output:
        {
            "analysis": "brief explanation in natural language if an attack is observed or indication that processes are suspicious but no coherent attack observed."
            "is_coherent_attack": "Yes / No"
        }
        """)

        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nAttack Processes:{final_processes}"
        }

        second_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )

        sec_res = second_response.choices[0].message.content.strip()
        return json.loads(sec_res)

    def get_list_of_activities(self, analysis):
        context = "Given a description of suspicious activities involving multiple processes, break down the described activities into individual dictionaries, specifying each observed action by the processes involved. Return a list of dictionaries called activities in json format"
        
        guidelines = """
            Example Input:
            The nginx process is seen performing various suspicious activities such as reading sensitive files (/etc/passwd), modifying files in the /tmp directory, and writing to /tmp/XIM. Subsequently, the inetd process executes the /tmp/XIM file, which is then read by the XIM process. The XIM process reads from /etc/libmap.conf, /var/run/ld-elf.so.hints, and /dev/urandom, and then sends data to an external IP address (53.158.101.118:80). This sequence of events suggests a coordinated attack where nginx is used to prepare and drop a malicious file, which is then executed and used to exfiltrate data.

            Expected Output:
            [
                {"process": "nginx", "action": "reading sensitive files (/etc/passwd)"},
                {"process": "nginx", "action": "modifying files in the /tmp directory"},
                {"process": "nginx", "action": "writing to /tmp/XIM"},
                {"process": "inetd", "action": "executes the /tmp/XIM file"},
                {"process": "XIM", "action": "reads the /tmp/XIM file"},
                {"process": "XIM", "action": "reads from /etc/libmap.conf, /var/run/ld-elf.so.hints, and /dev/urandom"},
                {"process": "XIM", "action": "sends data to an external IP address (53.158.101.118:80)"}
            ]

            Your Task:
            1. Read the provided input description of process activities.
            2. Identify and list each distinct activity performed by the processes.
            3. Format each identified activity as a dictionary, specifying the process involved and the action taken.
            4. Return the list of these dictionaries in json format.
        """

        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nInput:\n{analysis}"
        }

        activities_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )
        return activities_response.choices[0].message.content.strip()
    
    def get_mitre_response(self, activities):
        context = "You are a security researcher specializing in MITRE ATT&CK techniques and tactics. You have extensive knowledge of various cyber threats, attack patterns, and the corresponding TTPs (Tactics, Techniques, and Procedures) outlined in the MITRE ATT&CK framework. Your task is to map specific process actions to the appropriate MITRE TTPs based on your expertise.  Return the output in JSON format."

        guidelines = """
            I have a list of processes and their activities. Your task is to provide the correct MITRE TTP mappings for each activity. The mappings should correspond to the most relevant techniques from the MITRE ATT&CK framework.

            Tasks to perform:
            Analyze each process and its corresponding action.
            Identify the relevant MITRE Technique ID and it's description for each action. Ensure to use only MITRE Techniques and not any sub-techniques
            Provide a detailed mapping for each activity, ensuring accuracy and relevance.

            Expected Output:
            For each process and action provided, list the corresponding MITRE TTP(s) in a structured format, including the TTP ID and description. The output should be in JSON format.

            Example Input:
            [
                {"process": "nginx", "action": "reading sensitive files like '/etc/passwd'"},
                {"process": "nginx", "action": "modifying files in the '/tmp' directory"},
                {"process": "nginx", "action": "modifying the '/tmp/XIM' file"},
                {"process": "XIM", "action": "executed from the '/tmp/XIM' file"},
                {"process": "XIM", "action": "reads from '/dev/urandom'"},
                {"process": "XIM", "action": "sends data to an external IP address (53.158.101.118:80)"},
                {"process": "inetd", "action": "executes the '/tmp/XIM' file"},
                {"process": "sshd", "action": "executes the '/tmp/XIM' file"},
                {"process": "test", "action": "communicates with an external IP address (192.113.144.28:80)"}
            ]

            Example Output:
            [
                {"process": "nginx", "action": "reading sensitive files like '/etc/passwd'", "TTP": "T1003 - OS Credential Dumping"},
                {"process": "nginx", "action": "modifying files in the '/tmp' directory", "TTP": "T1105 - Ingress Tool Transfer"},
                {"process": "nginx", "action": "modifying the '/tmp/XIM' file", "TTP": "T1059 - Command and Scripting Interpreter"},
                {"process": "XIM", "action": "executed from the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "XIM", "action": "reads from '/dev/urandom'", "TTP": "T1001 - Data Obfuscation: Random Padding"},
                {"process": "XIM", "action": "sends data to an external IP address (53.158.101.118:80)", "TTP": "T1041 - Exfiltration Over C2 Channel"},
                {"process": "inetd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "sshd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "test", "action": "communicates with an external IP address (192.113.144.28:80)", "TTP": "T1102 - Web Service: Dead Drop Resolver"}
            ]
        """
        
        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nActivities:\n{activities}"
        }

        mitre_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )

        return mitre_response.choices[0].message.content.strip()

    def get_mitre_validation_from_llm(self, activities, result):
        context = "You are a security researcher specializing in MITRE ATT&CK techniques and tactics. You have extensive knowledge of various cyber threats, attack patterns, and the corresponding TTPs (Tactics, Techniques, and Procedures) outlined in the MITRE ATT&CK framework. Your task is to validate the specific process actions mapped to the MITRE TTPs by the LLM previously, based on your expertise.  Return the output in JSON format."

        guidelines = """
            I have a list of processes, their activities and their mappings. Your task is to check whether the correct MITRE TTP are mapped for each activity. The mappings should correspond to the most relevant techniques from the MITRE ATT&CK framework.

            Tasks to perform:
            Analyze each TTP mapped with the corresponding process and action.
            Check whether the TTPs are correct or incorrect.
            For TTPs incorrectly mapped, replace them with the correct TTP, ensuring accuracy and relevance. Ensure to use only MITRE Techniques and not any sub-techniques

            Expected Output:
            For each process and action provided, list the corresponding MITRE TTP(s) in a structured format, including the TTP ID and description. The output should be in JSON format.

            Example Input:
            [
                {"process": "nginx", "action": "reading sensitive files like '/etc/passwd'", "TTP": "T1003 - OS Credential Dumping"},
                {"process": "nginx", "action": "modifying files in the '/tmp' directory", "TTP": "T1105 - Ingress Tool Transfer"},
                {"process": "nginx", "action": "modifying the '/tmp/XIM' file", "TTP": "T1070 - Indicator Removal on Host: File Deletion"},
                {"process": "XIM", "action": "executed from the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "XIM", "action": "reads from '/dev/urandom'", "TTP": "T1001 - Data Obfuscation: Protocol Impersonation"},
                {"process": "XIM", "action": "sends data to an external IP address (53.158.101.118:80)", "TTP": "T1041 - Exfiltration Over C2 Channel"},
                {"process": "inetd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "sshd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "test", "action": "communicates with an external IP address (192.113.144.28:80)", "TTP": "T1102 - Web Service: Dead Drop Resolver"}
            ]

            Example Output:
            [
                {"process": "nginx", "action": "reading sensitive files like '/etc/passwd'", "TTP": "T1003 - OS Credential Dumping"},
                {"process": "nginx", "action": "modifying files in the '/tmp' directory", "TTP": "T1105 - Ingress Tool Transfer"},
                {"process": "nginx", "action": "modifying the '/tmp/XIM' file", "TTP": "T1059 - Command and Scripting Interpreter"},
                {"process": "XIM", "action": "executed from the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "XIM", "action": "reads from '/dev/urandom'", "TTP": "T1001 - Data Obfuscation: Random Padding"},
                {"process": "XIM", "action": "sends data to an external IP address (53.158.101.118:80)", "TTP": "T1041 - Exfiltration Over C2 Channel"},
                {"process": "inetd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "sshd", "action": "executes the '/tmp/XIM' file", "TTP": "T1204 - User Execution: Malicious File"},
                {"process": "test", "action": "communicates with an external IP address (192.113.144.28:80)", "TTP": "T1102 - Web Service: Dead Drop Resolver"}
            ]
            """

        system_prompt = {
            "role": "system",
            "content": context
        }

        user_prompt = {
            "role": "user",
            "content": f"{guidelines}\n\nActivities:\n{activities}\n\nMITRE Mapping:\n{result}"
        }

        mitre_validation_response = self.client.chat.completions.create(
            model=self.deployment,
            response_format={"type": "json_object"},
            messages=[system_prompt, user_prompt],
            temperature=0,
            seed=42
        )
        
        return mitre_validation_response.choices[0].message.content.strip()
    
    def get_mitre_ttps(self, analysis):
        try:
            response = json.loads(self.get_list_of_activities(analysis))
            activities = response["activities"]
        except Exception as e:
            print(e)
        
        #print(f"Activities: {activities}")

        try:
            mitre_response = json.loads(self.get_mitre_response(activities))
        except Exception as e:
            print(e)
        
        #print(f"MITRE Mapping: {mitre_response}")

        try:
            validated_mitre = json.loads(self.get_mitre_validation_from_llm(activities, mitre_response))
        except Exception as e:
            print(e)

        print(f"Validated MITRE Mapping: {validated_mitre}")