# NDR_Detection_Classifiers
A collection of detection queries and configuration data for use with Sophos NDR

I would like to add the ability for the NDR Sensor to run DDE detections from a git_repo so we do not have to create a cpp file for each new detection we add.

The repo would be structured similar to this:
<code> 
── detection-rules/                 <-- Base path for rules (configured in GIT_RULES_PATH_VAR)
│   ├── networkScan/                 <-- Directory named after the detection ID
│   │   ├── metadata.json            <-- Metadata for networkScan
│   │   └── query.sql                <-- The full SQL query for networkScan
│   ├── exfiltration/                <-- Directory named after the detection ID
│   │   ├── metadata.json            <-- Metadata for exfiltration
│   │   └── query.sql                <-- The full SQL query for exfiltration
│   ├── anomalous_tcp_scan/          <-- New directory for Anomalous TCP Flag Scan
│   │   ├── metadata.json
│   │   └── query.sql
├── README.md

<b>Sample metadata.json</b>
<code>
{
  "name": "Internal Host Recon - Aggressive Multi-Target/Multi-Port Scan",
  "id": "aggressive_scan",
  "description": "Detects an internal source IP engaging in highly aggressive and broad reconnaissance. This involves simultaneous scanning of many unique IP addresses and many unique ports using stealthy SYN probes, indicative of automated malicious activity.",
  "frequency_seconds": 3600
  "monitor_mode": 1
  "min_ndr_version": "1.10.1-3063"
  "execution_device": "NDR_Sensor"
}

<b>Sample query.sql</b>
<code>
/*
Name: Internal Host Recon - Aggressive Multi-Target/Multi-Port Scan
Description:
  Detects an internal source IP engaging in highly aggressive and broad reconnaissance.
  This involves simultaneous scanning of many unique IP addresses and many unique ports using stealthy SYN probes, indicative of automated malicious activity.
MITRE ATT&CK Mapping:
  T1595.001 - Active Scanning: Scanning IP Blocks/Ranges: High number of unique IPs scanned.
Severity Score: 5
Rationale:
  Highest confidence. This combines the breadth of IP scanning with the depth of port scanning, all in an aggressive, stealthy manner.
  This screams automated, malicious activity. Very low FP rate if thresholds are tuned correctly.
*/
SELECT
    'aggressive_scan' AS report_name,
    SrcIp,
    count(DISTINCT DestIp) AS Total_Unique_DestIPs,
    count(DISTINCT DestPort) AS Total_Unique_DestPorts,
    count() AS Total_Attempts,
    min(Timestamp) AS First_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} engaged in aggressive stealthy SYN scanning across {} IPs and {} ports, with {} total attempts. Automated reconnaissance suspected.', SrcIp, toString(count(DISTINCT DestIp)), toString(count(DISTINCT DestPort)), toString(count())) AS description,
    'T1595.001' AS mitre_mapping,
    5 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort))), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND ClientToServerPacketCount = 1
    AND ServerToClientPacketCount <= 1
    AND ClientToServerTcpFlags = 2
    AND (bitAnd(ServerToClientTcpFlags, 18) = 18 OR bitAnd(ServerToClientTcpFlags, 20) = 20 OR ServerToClientTcpFlags = 0)
    AND ClientToServerDuration < 500
GROUP BY
    SrcIp
HAVING
    count(DISTINCT DestIp) > 20
    AND count(DISTINCT DestPort) > 5
    AND count() > 50
ORDER BY
    Total_Attempts DESC
LIMIT 50;

We would add a cpp file to run the detections where they pull necessary data from the metadata and execute the query on the specified schedule

The intent is to allow us to publish new detections without the need for a software update and to support silent(monitor mode) where the query runs but does not create a detection that the customer sees in central. I think this requires us to set the monitor_mode field in the datalake when the results are sent to central. We should check how MDR_ops publishes and creates new SIGMA rules for detections.
