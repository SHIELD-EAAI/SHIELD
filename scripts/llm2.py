import json
import time
import random
import numpy as np
from openai import AzureOpenAI

class LLMAnalyzer:
    def __init__(self, client, deployment_name):
        """
        Initialize with Azure OpenAI client
        
        Args:
            client: AzureOpenAI client instance
            deployment_name: Name of the GPT deployment
        """
        self.client = client
        self.deployment_name = deployment_name

    def _call_azure_openai(self, messages, max_retries=3):
        """
        Call Azure OpenAI API with retry logic
        
        Args:
            messages: List of message dictionaries with role and content
            max_retries: Number of retry attempts
            
        Returns:
            str: Response from the model
        """
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.deployment_name,
                    messages=messages,
                    temperature=0.1,  # Low temperature for consistent security analysis
                    max_tokens=2000,
                    response_format={"type": "json_object"}  # Force JSON output
                )
                return response.choices[0].message.content
                
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # Exponential backoff
                    self.write_to_log(f"API call failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                    self.write_to_log(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    self.write_to_log(f"API call failed after {max_retries} attempts: {str(e)}")
                    raise

    def get_response_from_llm(self, data_string):
        context = "You are a security analyst tasked with identifying potentially malicious processes from system event logs. Your job is to analyze the logs and apply behavioral correlation rules to detect suspicious chains of activity that may indicate exploitation or compromise. Please provide the response in the json format"
        
        guidelines = """
            Objective:
                Given system event logs, determine if any process is involved in a potential attack by analyzing sequences of events across time. Focus on detecting behavior chains that suggest malicious intent, such as writing executable content to shared memory or temporary files, then executing from them.

            CRITICAL - Distinguishing Legitimate from Malicious Activity:
                Many processes perform network operations, file access, or system interactions as part of their NORMAL, INTENDED functionality.
                Do NOT flag processes simply for performing their designed function.
                
                Examples of LEGITIMATE behavior that should NOT be flagged:
                    - Email servers (IMAP/SMTP services) accessing mail directories and communicating on standard mail ports
                    - Mail clients reading/writing to user mailboxes and temporary files for drafts
                    - Web browsers communicating with external websites on HTTP/HTTPS ports
                    - Download utilities fetching files from the internet
                    - Shell processes maintaining command history files
                    - Local delivery agents writing incoming mail to user mailboxes
                
                ONLY flag processes when they exhibit behavior that is:
                    1. Outside their normal operational scope (e.g., a mail client executing binaries)
                    2. Part of a clear attack chain (e.g., Download utility fetching files and storing them in suspicious locations and executing them etc.)
                    3. Interacting with known attack patterns (e.g., privilege escalation sequences)

            Network Context:
                Internal/trusted network ranges that should NOT be considered suspicious:
                    - RFC 1918 private addresses (10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x)
                    - Local subnet communications (128.55.x.x or organization-specific ranges)
                    - Localhost/loopback communications (127.x.x.x, ::1)
                    - NETLINK and local IPC mechanisms
                
                Only flag external IP communications when combined with other suspicious indicators.

            Plan:
                1. Parse each log entry, which is formatted as:
                    processUUID,processName,event,objectUUID,objectData,dataflow,timestamp
                2. Identify individual actions and evaluate them in context:
                    - Is this action normal for this type of process?
                    - Does this action serve the process's intended purpose?
                    - Is this part of a suspicious sequence with other processes?
                3. Look for TRUE attack indicators:
                    - Write + Execute chains (especially in /tmp or web-accessible directories)
                    - Privilege escalation attempts
                    - Data staging before exfiltration
                    - Process injection or code injection patterns
                    - Unusual parent-child process relationships
                4. Output ONLY processes that show clear malicious intent or attack patterns

            Reasoning:
                You should flag a process if it exhibits anomalous behavior when viewed as a sequence of actions rather than isolated events. For example reflective loading or exploit staging.


            Output:
            {
                "attack_processes": ["processName1", "processName2"]
            }

            Please do not provide any explanation apart from the JSON object containing the `attack_processes` list (empty or otherwise).
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}"}

        messages = [system_prompt, user_prompt]
        return self._call_azure_openai(messages)

    def get_suspicious_operations_response_from_llm(self, data_string, process):
        context = "You are a security analyst tasked with identifying suspicious processes from a set of system event logs. The logs will be provided as input, and your job is to analyze them to determine whether a specific process is performing any suspicious or potentially malicious activity."
        
        guidelines = """
            Objective:
            Determine if a process action is suspicious based on the following criteria:

            Identify if the process is known or unknown.
                If the process is unknown, it should be marked as suspicious by default.

                If the process is known, evaluate its actions against expected behavior for that type of application or service.

            For a known process:
                Determine if the observed actions (e.g., read, write, execute, modify) align with typical operations for that process.
                
                Questions to ask:
                    - Is this what this type of application is designed to do?
                    - Would a security engineer expect this behavior from this process?
                    - Is there clear evidence of malicious intent beyond normal operation?
                If the action is consistent with the process's designed functionality = NOT suspicious

                Example: A browser like Firefox may read preferences files, write cache data, or perform network communication.
                
                If the action deviates significantly from what is normal for that process, it should be considered suspicious.
                    Look out for masquerading techniques such as file path spoofing.
                    Be alert to processes attempting to execute or modify directories that are conventionally used for data storage only.
                    Adversaries often use legitimate-looking file paths to hide malicious behavior.
                
                Watch for anomalous or unusual system interactions such as:
                    Writing to unexpected locations.
                    Performing unauthorized modifications.
                    Communicating with suspicious IP addresses.
                    Attempting to execute non-executable objects.

                Important Rule: Unless an action itself is anomalous for the process, the process should not be marked as suspicious.
                
                Consider the broader context and timeline of events.
                    Even if individual actions appear benign, consider how they fit into the overall sequence of events.
                    Look for patterns that suggest privilege escalation, lateral movement, or data exfiltration.
                
            Final determination:
                If the process is unknown, "isSuspicious": true.
                If the process is known but performs abnormal or unexpected actions, "isSuspicious": true.
                If the process is known and all actions align with expected behavior, "isSuspicious": false.
            
            Plan:
                Parse the input logs. Records are separated by ;, and fields by ,.
                Fields: processUUID, processName, event, objectUUID, objectData, dataflow, timestamp.
                Extract processName (2nd field) and event (3rd field).
                Determine if the process is known.
                    If unknown, mark as suspicious.
                    If known, check each event against a baseline of expected activities.
                    If any event deviates, mark as suspicious.
                Otherwise, mark as non-suspicious.

            Output:
            {
                "isSuspicious": true
            }

            Only return the JSON object in your response. 
            Do not include any additional text, explanation, or code.
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nAttack Process: {process}"}

        messages = [system_prompt, user_prompt]
        return self._call_azure_openai(messages)

    def get_validation_from_llm(self, data_string, attack_processes):
        context = "You are a security analyst tasked with identifying suspicious processes from a set of event logs. The event logs will be provided as input. Your job is to analyze them and validate whether the identified process/es are performing suspicious activities or not."

        guidelines = """
            Objective:
                Validate and expand the currently identified suspicious processes against the provided system logs. If necessary, adjust the list by adding or removing processes based on their actions within the logs and their role in the attack chain.

            Plan:
                1. Parse the input logs. Records are separated by ;, and fields by ,.
                    Fields: processUUID, processName, event, objectUUID, objectData, dataflow, timestamp.
                2. Analyze the given system event logs.
                3. Review the specified suspicious processes.
                4. Identify key attack chain patterns like parent processes that spawn suspicious children or processes that exhibit command-and-control behavior.
                5. If a process directly assists in the delivery, preparation, or execution of malicious payloads, it should be included as suspicious.
                6. Identify if any other processes in the logs perform unexpected actions and should be added to the suspicious list.
                7. If a process has been compromised or is clearly part of an attack sequence, it should be added or must remain in the suspicious list.
                8. If some currently identified suspicious processes appear to perform benign activity, remove them from the suspicious list.

            Output:
                A revised list of suspicious processes, for example:
                {
                    "attack_processes": ["p1", "p2", "p3"]
                }
            
            Example:
                System Event Logs:
                    "0,XIM,execute,0,/tmp/test,in,00:00:00.000;0,test,receive,1,192.113.144.28:80,in,00:00:00.030;0,test,fork,2,test,out,00:00:00.030;0,test,read,3,<unknown>,in,00:00:00.040;1,uname,write,3,<unknown>,out,00:00:00.040;"
                Attack Process/es: ['test', 'uname']
                
                Output expected:
                {
                    "attack_processes": ["XIM", "test", "uname"]
                }

                Reasoning:
                    test and uname are identified as suspicious. test is executed by XIM (0,XIM,execute,0,/tmp/test,in,00:00:00.000) hence XIM is added.
            
            Please do not provide any other explanation apart from the JSON object.
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nAttack Process/es: {attack_processes}"}

        messages = [system_prompt, user_prompt]
        return self._call_azure_openai(messages)

    def get_attack_description_from_llm(self, data_string, attack_processes):
        context = "You are a security analyst tasked with identifying coherent attacks from a set of event logs. The event logs will be provided as input along with suspicious processes. Your job is to analyze them and validate whether a coherent attack is found in the event logs or not."
        
        guidelines = """
            Objective:
                Analyze only the events from a given set of suspicious processes in the system logs to determine if they form a coherent attack sequence.

            Input:
                System logs with fields:
                    processUUID, processName, event, objectUUID, objectData, dataflow, timestamp
                    Records separated by ;
                    Fields separated by ,
                A list of suspicious processes to analyze.

            Analysis Steps:
                Filter the logs to include only events where processName matches a listed suspicious process.
                If there is more than one suspicious process, check if they interact to increase confidence in a coherent attack.
                If there is only one suspicious process, be less confident (lower probability) unless its actions clearly form an attack pattern.
                Examine the sequence of events these suspicious processes perform to determine if they collectively indicate a coherent attack pattern (e.g., reconnaissance, exploitation, data exfiltration).

            Output Format:
            {
                "is_coherent_attack_present": true,
                "attack_description": "Short explanation of why the suspicious processes form or do not form an attack",
                "analysis_probability": 0.85
            }

            Rules:
                Consider only the events from suspicious processes.
                Ignore all events from non-suspicious processes.
                The conclusion depends solely on the suspicious processes' events.
                Multiple interacting suspicious processes = higher confidence.
                Single suspicious process with no clear attack pattern = lower confidence.
                analysis_probability reflects how sure you are about the presence of an attack (0.0 to 1.0).
            
            Do not output code and provide only the JSON response.
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nSuspicious Process/es: {attack_processes}"}

        messages = [system_prompt, user_prompt]
        return self._call_azure_openai(messages)

    def process_get_final_conclusion(self, data_string, final_processes):
        context = "You are a security analyst tasked with validating potential attacks within a set of event logs. The event logs and the identified attack processes will be provided as input. Your job is to analyze the logs related to these processes and determine whether they form a coherent attack. If there is a coherent attack observed also provide a probability score. Flag all the process_uuids that form part of the attack. Provide the response in JSON format."

        guidelines = """
            Guidelines: Each record in the event logs is separated by semicolons, and fields within records are separated by commas. The fields are:

            - 'processUUID': Unique ID for the process
            - 'processName': Name of the process
            - 'event': Type of operation performed (read, write, execute, modify, send, receive, fork)
            - 'objectUUID': Unique ID for the object
            - 'objectData': Details of the object on which the operation was performed
            - 'dataflow': 'in' indicates data coming into the process, 'out' indicates the process sending data
            - 'timestamp': Time from the start of the logs captured in minutes

            Context to be applied during analysis:
                - File operations: Logs are system level logs. Focus on connections between user level objects.
                - Network operations: Internal IP Range wherein traffic is accepted and expected -> Internal IPs, NETLINK:0 communication and IP range 128.55 are Internal IPs.

            How to determine coherence in the attack indicators:
                - Coherence is determined with the sequence of events which are related to each other.
                - For example: Process1 writes to Object1 and Process2 reads from Object1 or Process1 communicates with IP1 and Process2 also communicates with IP1.
                - Focus on connections between user level objects.
            
            Probability Score: 
                Assign a probability score representing the likelihood that the detected attack scenario is accurate and valid.
                    Complete attack chain detected (Exploitation to C2): probability_score >= 0.9
                    Partial attack sequence identified: 0.8 <= probability_score < 0.9
                    Suspicious coherence detected: 0.7 <= probability_score < 0.8  
            
            Please note to flag only those UUIDs that actually form the attack. For example, there are multiple instances of explorer.exe but only 1 is involved in the attack. Ignore the others and send UUID of that process that is part of the attack for easier triage.

            Output:
            {
                "process_uuids": ["uuid1", "uuid2", "uuid3"],
                "probability_score": 0.85
            }
            
            Do not output code and provide only the JSON response.
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}\n\nAttack Process/es: {final_processes}"}

        messages = [system_prompt, user_prompt]
        self.write_to_log("Getting final conclusion from LLM...")
        return self._call_azure_openai(messages)

    def process_get_result_from_llm(self, data_string):
        context = """You are a security analyst specializing in detecting cyber attacks based on event logs. You will be provided with a set of event logs formatted as (process, event, object, timestamp). Each log entry indicates a specific operation performed by a process on an object at a given time. Please provide the response in the json format.
        
        Your task is to:
        1. Determine Coherence: Analyze the sequence of events to decide if they form a coherent attack.
        2. Describe the Attack: Identify specific IP addresses, files, or objects that were targeted. Summarize how processes interacted with these objects. Map actions to stages in the cyber kill chain.
        3. Probability Score: Assign a probability score (0.0 to 1.0) representing the likelihood that the detected attack scenario is accurate.
        """

        guidelines = """
        Assessing Coherence:
            Coherence is established by analyzing the sequence of events to determine if they are interconnected. Example:
                If process1 and process2 are identified as potential attack processes, check if they are interacting with the same or related objects:
                    Process1 writes to Object1, and Process2 reads from Object1.
                    Process1 communicates with IP1, and Process2 also communicates with IP1.
                
                Note: The logs are system-level logs. Most processes will naturally access similar system-level objects during normal operations. Focus on identifying connections between user-level objects that are less common and more likely to indicate an attack.

        Output Format:
        {
            "is_coherent_attack": true,
            "description": "Description of the attack",
            "probability_score": 0.85
        }
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"{guidelines}\n\nSystem Event Logs:\n{data_string}"}

        messages = [system_prompt, user_prompt]
        self.write_to_log("Getting attack analysis from LLM...")
        return self._call_azure_openai(messages)

    def validate_attack(self, data_string: str, processes: list) -> tuple:
        """Validate if processes are suspicious and get final validation."""
        for process in processes:
            try:
                result_str = self.get_suspicious_operations_response_from_llm(data_string, process)
                result = json.loads(result_str)
                
                if result.get('isSuspicious'):
                    try:
                        final_str = self.get_validation_from_llm(data_string, processes)
                        final = json.loads(final_str)
                        return True, final
                    except json.JSONDecodeError as e:
                        self.write_to_log(f"JSON decode error validating process {process}: {str(e)}")
                        self.write_to_log(f"Raw response: {final_str}")
                        continue
                    except Exception as e:
                        self.write_to_log(f"Error validating process {process}: {str(e)}")
                        continue
                        
            except json.JSONDecodeError as e:
                self.write_to_log(f"JSON decode error for suspicious process {process}: {str(e)}")
                self.write_to_log(f"Raw response: {result_str}")
                continue
            except Exception as e:
                self.write_to_log(f"Error checking suspicious process {process}: {str(e)}")
                continue
                
        return False, None

    def write_to_log(self, message):
        """Write log message with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

    def main(self, data_string):
        """Main analysis pipeline"""
        try:
            self.write_to_log("Starting LLM analysis...")
            
            # Step 1: Get initial attack processes
            response = self.get_response_from_llm(data_string)
            result = json.loads(response)
            attack_processes = result.get('attack_processes', [])
            
            if not attack_processes:
                self.write_to_log("No attack processes found")
                return [], None
            
            self.write_to_log(f"Initial attack processes found: {attack_processes}")
            
            # Step 2: Validate attack processes
            is_attack, final = self.validate_attack(data_string, attack_processes)
            
            if not is_attack or not final:
                self.write_to_log("Attack validation failed")
                return [], None
            
            # Step 3: Get final validated processes
            attack_procs = final.get('attack_processes', [])
            self.write_to_log(f"Validated processes: {attack_procs}")
            
            # Step 4: Get attack description and probability
            final_result_str = self.get_attack_description_from_llm(data_string, attack_procs)
            final_result = json.loads(final_result_str)
            self.write_to_log(f"Attack analysis complete: {final_result}")
            
            return attack_procs, final_result
            
        except json.JSONDecodeError as e:
            self.write_to_log(f"JSON decode error in main processing: {str(e)}")
            return [], None
        except Exception as e:
            self.write_to_log(f"Error in main processing: {str(e)}")
            import traceback
            traceback.print_exc()
            return [], None