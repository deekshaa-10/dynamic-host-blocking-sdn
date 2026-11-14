# Multi-Attacker Robustness Testing

## 1. Objective

The objective of Deliverable 2 is to extend the existing Mininet topology to support three simultaneous attackers and test whether the Dynamic Host Blocking System can detect and block them independently.

The experiment also verifies that legitimate clients can continue communicating with the TCP server during an attack.

## 2. Updated Topology

The topology consists of one OpenFlow 1.3 switch, two legitimate clients, three attackers and one TCP server.

| Host | IP Address | Role |
|---|---|---|
| n1 | 10.0.0.1 | Normal client |
| n2 | 10.0.0.2 | Normal client |
| atk | 10.0.0.3 | Attacker 1 |
| srv | 10.0.0.4 | TCP server |
| atk2 | 10.0.0.5 | Attacker 2 |
| atk3 | 10.0.0.6 | Attacker 3 |

All six hosts are connected to the same switch, s1.

The Ryu controller communicates with the switch using OpenFlow 1.3 on port 6653.

## 3. Testing Procedure

1. Start the Ryu D2 controller.
2. Clean previous Mininet state using `sudo mn -c`.
3. Start the updated topology using `sudo python3 topology/topology.py`.
4. Verify all six hosts and their IP addresses.
5. Start the TCP server on srv.
6. Start legitimate client traffic from n1.
7. Record the initial OpenFlow flow table.
8. Launch atk, atk2 and atk3 simultaneously.
9. Inspect controller logs for separate BLOCK events.
10. Inspect the OpenFlow flow table for DROP rules.
11. Test connectivity from n2 to the TCP server.
12. Observe automatic unblocking after the timeout.

Each attacker generates TCP connection requests at a configured rate of 50 per second for 20 seconds.

## 4. Expected Results

- All six hosts should be created successfully.
- The controller should detect all three attackers independently.
- Separate BLOCK events should be generated for 10.0.0.3, 10.0.0.5 and 10.0.0.6.
- Three priority-100 DROP rules should be installed.
- STATUS should show `blocked=3` if all three blocking periods overlap when the status is recorded.
- Legitimate clients should continue communicating with the server.
- Expired blocking rules should be removed automatically.

## 5. Actual Results

(To be completed after executing the experiment.)

| Test | Actual Observation | Status |
|---|---|---|
| Six-host topology | [Enter result] | [PASS/FAIL] |
| Attacker 1 blocking | [Enter result] | [PASS/FAIL] |
| Attacker 2 blocking | [Enter result] | [PASS/FAIL] |
| Attacker 3 blocking | [Enter result] | [PASS/FAIL] |
| Three simultaneous blocks | [Enter result] | [PASS/FAIL/NOT VERIFIED] |
| OpenFlow DROP rules | [Enter result] | [PASS/FAIL] |
| n1 legitimate traffic | [Enter result] | [PASS/FAIL] |
| n2 connectivity | [Enter result] | [PASS/FAIL] |
| Automatic unblocking | [Enter result] | [PASS/FAIL/NOT VERIFIED] |

## 6. Evidence

The following evidence will be collected during testing:

1. Controller startup screenshot.
2. Updated six-host Mininet topology.
3. Host IP address verification.
4. Three attacker processes running.
5. Controller logs showing individual BLOCK events.
6. STATUS log showing three simultaneously blocked hosts, if observed.
7. OpenFlow flow table showing attacker DROP rules.
8. Successful ACK replies from legitimate client n1.
9. Successful connectivity test from n2.
10. UNBLOCK events and final flow table, if verified.

## 7. Conclusion

(To be completed after testing.)

The experiment evaluates whether the Dynamic Host Blocking System can handle multiple attackers independently while preserving legitimate network communication.

The final conclusion will be based on the actual controller logs, OpenFlow rules and connectivity test results.
