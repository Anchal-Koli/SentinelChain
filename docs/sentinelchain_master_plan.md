# SentinelChain Master Execution Plan (Sept - Dec)

This is the exact sequential roadmap for developing the SentinelChain (Packet-Level LLM Forensics) project.

## PHASE A — September (Infrastructure & Graph Reconstruction)
1. **Event schema:** Define standardized JSON schemas for network events.
2. **Suricata listener:** Develop a daemon to hook Suricata alerts.
3. **Zeek listener:** Develop a daemon to hook Zeek logs.
4. **Event normalizer:** Normalize both Suricata and Zeek data into the standard event schema.
5. **Selective TShark extractor:** Trigger tshark to extract selective PCAP slices based on events.
6. **Evidence storage:** Store the extracted packet slices and normalized events efficiently.
7. **NetworkX graph:** Initialize the causal transition graph using NetworkX.
8. **Transition rules:** Define the rules that connect different network events (nodes) to form edges.
9. **Transition scoring:** Implement scoring mechanisms for edges based on time, IP, and protocol correlations.
10. **Causal chain reconstruction:** Traverse the graph to reconstruct the full attack chain.

## PHASE B — October (Benchmarking & Baselines)
11. **HOLMES-style baseline:** Implement a baseline system inspired by the HOLMES paper for comparison.
12. **Ground-truth scenarios:** Curate ground-truth labels for the 3 core attack chains.
13. **Benchmark runner:** Develop an automated script to run scenarios against the engine.
14. **Precision/Recall/F1:** Calculate standard ML metrics for the causal chain reconstruction.
15. **False-positive analysis:** Analyze instances where benign traffic was flagged.
16. **DPI volume/latency measurement:** Measure the computational overhead of selective DPI vs full packet inspection.
17. **Conference paper:** Draft the conference paper outlining Phase A and Phase B findings.

## PHASE C — November (LLM Integration & Explainability)
18. **Evidence Pack:** Compile the Evidence Pack from the causal chain and PCAP slices.
19. **Retrieval layer:** Implement a retrieval mechanism (Vector DB or direct querying) for the Evidence Pack.
20. **LLM reporting:** Generate explainable incident reports using the LLM.
21. **Claim extraction:** Extract specific claims made by the LLM in its report.
22. **Evidence matching:** Match extracted claims against the Evidence Pack to ensure grounding.
23. **Forensic Groundedness Score:** Calculate a score representing how well the LLM's claims are backed by evidence (Quote Rule).
24. **Validate → Retry:** Implement a closed-loop system where the LLM self-corrects if groundedness is low.

## PHASE D — December (Refinement & Final Evaluation)
25. **Analyst feedback:** Incorporate human-in-the-loop (HITL) feedback mechanisms.
26. **Rule weight update:** Dynamically adjust transition scoring rules based on feedback.
27. **Ablation study:** Conduct ablation studies to determine the impact of each system component.
28. **Full evaluation:** Run the final end-to-end evaluation across all datasets.
29. **Results visualization:** Create graphs, charts, and visualizations of the metrics and causal chains.
30. **Journal paper:** Draft the final comprehensive journal paper.
