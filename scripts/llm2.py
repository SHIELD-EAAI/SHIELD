import json
import time
import torch # type: ignore
import random
import numpy as np # type: ignore

class LLMAnalyzer:
    def __init__(self, tokenizer=None, pipe=None):
        self.tokenizer = tokenizer
        self.pipe = pipe

    def get_response_from_llm(self, data_string):
        context = "You are a security analyst tasked with identifying potentially malicious processes from system event logs. Your job is to analyze the logs and apply behavioral correlation rules to detect suspicious chains of activity that may indicate exploitation or compromise."
        
        guidelines = """
            

            Objective:
                Given system event logs, determine if any process is involved in a potential attack by analyzing sequences of events across time. Focus on detecting behavior chains that suggest malicious intent, such as writing executable content to shared memory or temporary files, then executing from them.

            Plan:
                1. Parse each log entry, which is formatted as:
                    processUUID,processName,event,objectUUID,objectData,dataflow,timestamp
                2. Identify individual suspicious actions such as:
                    - Writing to shared memory or shared files.
                    - Executing from non-standard locations.
                    - Unusual network communication.
                3. Apply behavioral correlation rules and correlate events across timestamps to identify attack chains.
                5. Output a JSON object listing all suspicious processes under "attack_processes".

            Reasoning:
                You should flag a process if it exhibits anomalous behavior when viewed as a sequence of actions rather than isolated events. For example reflective loading or exploit staging.

            Output:
            {
                "attack_processes": ["processName1", "processName2"]
            }

            Please do not provide any explanation apart from the JSON object containing the `attack_processes` list (empty or otherwise). I need to forward this to the next phase of my lifecycle.
                            
            """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}"}

        messages = [system_prompt, user_prompt]
        #print(messages)
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]

        return result

    def get_suspicious_operations_response_from_llm(self, data_string, process):
        context = "You are a security analyst tasked with identifying suspicious processes from a set of system event logs. The logs will be provided as input, and your job is to analyze them to determine whether a specific process is performing any suspicious or potentially malicious activity."
        
        guidelines = """
            Objective:
            Determine if a process action is suspicious based on the following criteria:

            Identify if the process is known or unknown.
                If the process is unknown, it should be marked as suspicious by default.
                If the process is known, evaluate its actions against expected behavior for that type of application or service.
                Evaluate the process's actions against expected behavior.

            For a known process:
                Determine if the observed actions (e.g., read, write, execute, modify) align with typical operations for that process.
                Example: A browser like Firefox may read preferences files, write cache data, or perform network communication.
                
                If the action deviates significantly from what is normal for that process, it should be considered suspicious.
                    Look out for masquerading techniques such as file path spoofing.
                    Be alert to processes attempting to execute or modify directories that are conventionally used for data storage only.
                    Adversaries often use legitimate-looking file paths to hide malicious behavior, making it appear as part of normal process activity.
                Watch for anomalous or unusual system interactions.
                Actions such as:
                    Writing to unexpected locations.
                    Performing unauthorized modifications.
                    Communicating with suspicious IP addresses.
                    Attempting to execute non-executable objects.

                These behaviors should raise suspicion unless there is clear justification within the context of the process.

                Important Rule: Unless an action itself is anomalous for the process, the process should not be marked as suspicious. This means speculative risks, must not lead to a "suspicious" label unless directly supported by concrete evidence in the logs.
                
                Consider the broader context and timeline of events.
                    Even if individual actions appear benign, consider how they fit into the overall sequence of events.
                    Look for patterns that suggest privilege escalation, lateral movement, or data exfiltration.
                    
                    Use baseline knowledge of common applications and their behaviors.
                        Browsers typically interact with cache, shared preferences, and safe browsing databases.
                        Messaging apps may access SMS services or contact databases.
                        Deviations from these norms should be flagged as suspicious.
                
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
                        If known, check each event against a baseline of expected activities for that process type.
                        If any event deviates from expected activity mark as suspicious.
                    Otherwise, mark as non-suspicious.
                
                Reasoning:
                    Unknown processes are inherently risky.
                    Even known processes can be co-opted or behave abnormally.
                    Limiting suspicious behavior to actions outside the normal scope for a known process provides a finer-grained and more accurate detection mechanism.

            Output:
            {
                "isSuspicious": true
            }

            Only return the JSON object in your response. 
            Do not include any additional text, explanation, or code. 
            Base your judgment strictly on the provided logs and your knowledge of normal process behavior.
            """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}\nAttack Process: {process}"}

        messages = [system_prompt, user_prompt]
        
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]

        return result

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
                4. Identify key attack chain patterns that are missed out like parent processes that spawn suspicious children or processes that exhibit command-and-control behavior
                5. If a process directly assists in the delivery, preparation, or execution of malicious payloads, it should be included as suspicious.
                6. Identify if any other processes in the logs perform unexpected actions and should be added in suspicious list.
                7. If a process has been compromised or is clearly part of an attack sequence, should be added or must remain in the suspicious list.
                8. If some currently identified suspicious processes appear to peroform benign activity, remove them from the suspicious list.


            Output:
                A revised list of suspicious processes, for example:
                {
                    "attack_processes": ["p1", "p2"', "p3"]
                }
            
            Example:
                System Event Logs:
                    System Event Logs: "0,MIX,execute,0,/tmp/crest,in,00:00:00.000;0,crest,receive,1,192.113.144.28:80,in,00:00:00.030;0,crest,fork,2,crest,out,00:00:00.030;0,crest,read,3,<unknown>,in,00:00:00.040;1,username,write,3,<unknown>,out,00:00:00.040;"
                    Attack Process/es: ['crest', 'username']
                
                Output expected from assistant:
                {
                    "attack_processes": ["MIX", "crest", "username"]
                }

                Reasoning:
                    here crest and username are identified as suspicious processes. crest is executed by MIX (0,MIX,execute,0,/tmp/crest,in,00:00:00.000) hence MIX is added. 
            Please do not provide any other explanation apart from the Json object. Do not write or output code.
            """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}\nAttack Process/es: {attack_processes}"}

        messages = [system_prompt, user_prompt]
        #print(messages)
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]
        return result

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
                "is_coherent_attack_present": true/false,
                "attack_description": "Short explanation of why the suspicious processes form or do not form an attack",
                "analysis_probability": 0.0 to 1.0
            }
            Do not output code and provide only the Json response, no additional information required

            Rules:
                Consider only the events from suspicious processes.
                Ignore all events from non-suspicious processes.
                The conclusion depends solely on the suspicious processes' events.
                Multiple interacting suspicious processes = higher confidence.
                Single suspicious process with no clear attack pattern = lower confidence.
                analysis_probability reflects how sure you are about the presence of an attack.
            """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}\nSuspicious Process/es: {attack_processes}"}

        messages = [system_prompt, user_prompt]
        #print(messages)
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]

        return result
	
	
    def process_get_final_conclusion(self, data_string, final_processes):
        context = "You are a security analyst tasked with validating potential attack within a set of event logs. The event logs and the identified attack processes will be provided as input. Your job is to analyze the logs related to these processes and determine whether they form a coherent attack. If there is a coherent attack observed also provide a probability score attached to it. Flag all the process_uuids that forms the part of the attack. Provide the response in json format"

        guidelines = """
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
            
            Context to be applied during analysis:
                - File operations
                    - Logs are system level logs. Hence keep in mind that many of them may be accessing system files. Therefore focus on connections between user level objects.
                - Network operations         
                    - Internal IP Range wherein traffic is accepted and expected -> Internal IPs, NETLINK:0 communication and IP range 128.55 are Internal IPs.

            How to determine coherence in the attack indicators:
                - Coherence is determined with the sequence of events which are related to each other.
                - For example we have process1 and process2 as part of attack_processes. We check whether they are performing operations on related objects. Process1 writes to Object1 and Process2 reads from Object1 or Process1 communicates with IP1 and Process2 also communicates with IP1.
                - Please keep in mind that the logs are system level logs, hence it is important to note that most processes will try to access similar system level objects during runtime. Therefore focus on connections between user level objects
            
            Probability Score: 
                Assign a probability score representing the likelihood that the detected attack scenario is accurate and valid. 
                Output: 
                    A probability_score field with a numerical value (0.0 to 1.0) indicating the confidence level in the attack's coherence. 
                         Complete attack chain detected (Exploitation to C2): probability_score >= 0.9
                         Partial attack sequence identified: 0.8 <= probability_score < 0.9
                         Suspicious coherence detected: 0.7 <= probability_score < 0.8  

            
            Please note to flag only those uuids that actually form the attack. For example there are multiple instances of winexplorer but only 1 is involved in the attack, Ignore the others and send uuid of that process that is part of the attack for easier triage. 

            Output:
            {
                "process_uuids: ["uuid1", "uuid2", "uuid3"]
                "probability_score": float
            }
            Do not output code and provide only the Json response, no additional information required
            """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}\nAttack Process/es: {final_processes}"}

        messages = [system_prompt, user_prompt]
        print("Final Result Found")
        print(messages)
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]

        return result
	

    def process_get_result_from_llm(self, data_string):
        context = """You are a security analyst specializing in detecting cyber attacks based on event logs. You will be provided with a set of event logs formatted as (process, event, object, timestamp). Each log entry indicates a specific operation (such as read, write, send, or receive) performed by a process on an object (like a file or socket) at a given time.
            Your task is to:

            1. Determine Coherence: Analyze the sequence of events to decide if they form a coherent attack.
                Output: A boolean value, is_coherent_attack, indicating whether the events constitute a coherent attack (True or False).

            2. Describe the Attack:
                    Objects and Actions: Identify the specific IP addresses, files, or other objects that were targeted or affected during the attack.
                    Sequence of Events: Summarize how the processes interacted with these objects or communicated with external entities, highlighting any suspicious or malicious behaviors.
                    Mapping to the Attack Kill Chain: Relate the actions to stages in the cyber kill chain (e.g., reconnaissance, delivery, exploitation, etc.) to provide context on the attack's progression.
                    If the events do not form a coherent attack, state that the processes are suspicious but do not form a coherent attack.
                Output: A description field with a concise summary of the attack scenario, including the relevant objects, actions, and how they map to the attack kill chain.

            3. Probability Score: Assign a probability score representing the likelihood that the detected attack scenario is accurate and valid.
                Output: A probability_score field with a numerical value (0.0 to 1.0) indicating the confidence level in the attack's coherence.
        """

        guidelines = """Assessing Coherence:

            Coherence is established by analyzing the sequence of events to determine if they are interconnected. Example: 
                If process1 and process2 are identified as potential attack processes, check if they are interacting with the same or related objects. For instance:
                    Process1 writes to Object1, and Process2 reads from Object1.
                    Process1 communicates with IP1, and Process2 also communicates with IP1.
                Note: The logs provided are system-level logs. Most processes will naturally access similar system-level objects during normal operations. Therefore, focus on identifying connections between user-level objects (such as files, IPs, or specific user actions) that are less common and more likely to indicate an attack.

        Output Format: Provide your analysis in the following JSON structure:
        {
            "is_coherent_attack": boolean,
            "description": "string",
            "probability_score": float
        }
        """

        system_prompt = {"role": "system", "content": context}
        user_prompt = {"role": "user", "content": f"content: {guidelines}\n\nSystem Event Logs:\n{data_string}"}

        messages = [system_prompt, user_prompt]
        print("Process Response LLM")
        print(messages)
        
        if self.tokenizer and self.pipe:
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            outputs = self.pipe(prompt)
            result = outputs[0]["generated_text"][len(prompt):]

        return result
	
	
    def validate_attack(self, data_string: str, processes: list) -> tuple:
        """Validate if processes are suspicious and get final validation."""
        for process in processes:
            try:
                result_str = self.get_suspicious_operations_response_from_llm(data_string, process)
                result = json.loads(result_str)
                #print(result)
                if result.get('isSuspicious'):
                    try:
                        final_str = self.get_validation_from_llm(data_string, processes)
                        final = json.loads(final_str)
                        return True, final
                    except Exception as e:
                        self.write_to_log(f"Error validating process {process}: {str(e)}")
                        self.write_to_log(f"Details: {final_str}")
                        continue
            except Exception as e:
                self.write_to_log(f"Error in suspicious process {process}: {str(e)}")
                self.write_to_log(f"Details: {result_str}")
                continue
        return False, None

    def write_to_log(self, message):
        # Implement your logging logic here
        print(message)  # Simple print for now, replace with actual logging

    def main(self, data_string):
        try:
            response = self.get_response_from_llm(data_string)
            result = json.loads(response)
            #print(result)
            attack_processes = result.get('attack_processes', [])
            #self.write_to_log(f"Attack processes found: {attack_processes}")
            if attack_processes:
                is_attack, final = self.validate_attack(data_string, attack_processes)
                if is_attack and final:
                    try:
                        attack_procs = final.get('attack_processes', [])
                        #self.write_to_log(f"Validated processes found: {attack_procs}")
                        final_result_str = self.get_attack_description_from_llm(data_string, attack_procs)
                        final_result = json.loads(final_result_str)
                        #self.write_to_log(f"Final Result found: {final_result}")
                        return attack_procs, final_result
                    except Exception as e:
                        self.write_to_log(f"Error processing final result: {str(e)}")
                        self.write_to_log(f"Raw final value: {final_result_str}")
            
            return [], None
            
        except Exception as e:
            self.write_to_log(f"Error in main processing: {str(e)}")
            return [], None
        finally:
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            time.sleep(1)