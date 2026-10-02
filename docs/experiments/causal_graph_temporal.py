import networkx as nx
import sqlite3
from datetime import datetime

class CausalCorrelationEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.graph = nx.DiGraph()

        # Maximum allowed time gap between causally related events.
        # Initial research prototype value: 5 minutes.
        self.max_time_gap_seconds = 300
        
        # MITRE / State Machine Mapping
        # Defines valid state transitions and weights
        self.valid_transitions = {
            "Reconnaissance": ["Lateral Movement", "Initial Access", "Privilege Escalation"],
            "Initial Access": ["Execution", "Persistence", "Privilege Escalation", "Lateral Movement"],
            "Execution": ["Persistence", "Privilege Escalation", "Lateral Movement", "Defense Evasion"],
            "Privilege Escalation": ["Defense Evasion", "Credential Access", "Discovery", "Lateral Movement"],
            "Defense Evasion": ["Discovery", "Lateral Movement", "Collection", "Command and Control"],
            "Credential Access": ["Discovery", "Lateral Movement", "Collection"],
            "Discovery": ["Lateral Movement", "Collection"],
            "Lateral Movement": ["Execution", "Collection", "Command and Control"],
            "Collection": ["Exfiltration", "Command and Control"],
            "Command and Control": ["Exfiltration", "Impact"],
            "Exfiltration": ["Impact"],
            "Impact": []
        }
        
    def load_alerts(self):
        """Loads alerts from SQLite database to build the correlation graph."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dest_ip, signature, category, severity FROM suricata_alerts ORDER BY timestamp ASC")
        rows = cursor.fetchall()
        conn.close()
        return rows
        
    def map_category_to_tactic(self, category):
        """
        Maps only explicitly recognized Suricata categories to
        high-level ATT&CK tactics.

        Unknown or ambiguous categories remain Unknown rather
        than being forced into an unsupported tactic.
        """
        category = str(category or "").strip().lower()

        explicit_mapping = {
            "network scan": "Reconnaissance",
            "web application attack": "Initial Access",
            "attempted administrator privilege gain": "Privilege Escalation",
            "command and control": "Command and Control",
            "data exfiltration": "Exfiltration",
        }

        return explicit_mapping.get(category, "Unknown")

    def build_graph(self):
        rows = self.load_alerts()
        previous_nodes = {}

        for index, row in enumerate(rows):
            node_id = f"alert_{index}"
            tactic = self.map_category_to_tactic(row["category"])

            self.graph.add_node(
                node_id,
                timestamp=row["timestamp"],
                src_ip=row["src_ip"],
                dest_ip=row["dest_ip"],
                signature=row["signature"],
                tactic=tactic,
                severity=row["severity"]
            )

            ip_pair = tuple(
                sorted([row["src_ip"], row["dest_ip"]])
            )

            if ip_pair in previous_nodes:
                prev_node_id = previous_nodes[ip_pair]
                prev_node = self.graph.nodes[prev_node_id]

                prev_tactic = prev_node["tactic"]

                # Parse timestamps for temporal correlation.
                previous_time = datetime.strptime(
                    prev_node["timestamp"],
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )

                current_time = datetime.strptime(
                    row["timestamp"],
                    "%Y-%m-%dT%H:%M:%S.%f%z"
                )

                time_gap = (
                    current_time - previous_time
                ).total_seconds()

                valid_next_stages = self.valid_transitions.get(
                    prev_tactic,
                    []
                )

                valid_transition = (
                    prev_tactic != "Unknown"
                    and tactic != "Unknown"
                    and tactic in valid_next_stages
                )

                valid_time = (
                    time_gap > 0
                    and time_gap <= self.max_time_gap_seconds
                )

                if valid_transition and valid_time:
                    self.graph.add_edge(
                        prev_node_id,
                        node_id,
                        weight=1.0,
                        time_gap_seconds=time_gap
                    )

            previous_nodes[ip_pair] = node_id

        print(
            f"Graph built with "
            f"{self.graph.number_of_nodes()} nodes and "
            f"{self.graph.number_of_edges()} edges."
        )

    def analyze_attack_chains(self):
        """Finds paths with high correlation weights, representing valid attack chains."""
        print("Analyzing causal attack chains...")
        chains = []
        for component in nx.weakly_connected_components(self.graph):
            subgraph = self.graph.subgraph(component)
            if len(subgraph.nodes) > 1:
                try:
                    longest_path = nx.dag_longest_path(subgraph, weight='weight')
                    chains.append(longest_path)
                except nx.NetworkXUnfeasible:
                    pass
                    
        for i, chain in enumerate(chains):
            print(f"\n--- Attack Chain {i+1} ---")
            for node in chain:
                n_data = self.graph.nodes[node]
                print(f" -> {n_data['timestamp']} | {n_data['tactic']} ({n_data['signature']}) | {n_data['src_ip']} to {n_data['dest_ip']}")

if __name__ == "__main__":
    import os
    db_path = os.environ.get("DB_PATH", "/workspace/capture/forensics.db")
    if os.path.exists(db_path):
        engine = CausalCorrelationEngine(db_path)
        engine.build_graph()
        engine.analyze_attack_chains()
    else:
        print(f"Database not found at {db_path}. Please run ingest_logs.py first.")
