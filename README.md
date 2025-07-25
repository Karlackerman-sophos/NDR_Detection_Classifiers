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
```json
{
  "id": "udp_app_scan",
  "name": "Internal Host Recon - UDP Application Scan",
  "description": "Detects an internal source IP attempting to probe a high number of unique UDP ports on a destination, specifically for known application protocols like DNS, NTP, or SSDP. This indicates targeted reconnaissance against specific UDP services.",
  "enabled": true,
  "frequency_seconds": 3600,
  "monitor_mode": 1,
  "execution_device": "NDR_Sensor",
  "min_ndr_version": "1.10.1-3063",
  "mitre_attack_mapping": "T1046",
  "severity_score_default": 4,
  "apply_global_ip_exclusions": true
}
```

<b>Sample query.sql</b>
```sql
/*
Name: Internal Host Recon - UDP Application Scan
Description:
  Detects an internal source IP attempting to probe a high number of unique UDP ports on a destination,
  specifically for known application protocols like DNS, NTP, or SSDP.
  This indicates targeted reconnaissance against specific UDP services.
MITRE ATT&CK Mapping:
  T1046 - Network Service Discovery: Directly applicable, as the goal is to find active UDP services.
Severity Score: 4
Rationale:
  UDP scans are less common than TCP scans in legitimate applications but are routinely used by attackers.
  A high volume of UDP probes from an internal source is highly suspicious.
*/
SELECT
    'udp_app_scan' AS report_name,
    SrcIp,
    DestIp,
    MasterProtocol,
    SubProtocol,
    count(DISTINCT DestPort) AS Unique_DestPorts_Scanned,
    min(Timestamp) AS First_Scan_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} performed UDP scan against {} targeting {} unique ports for {} ({}). UDP service discovery suspected.', SrcIp, DestIp, toString(count(DISTINCT DestPort)), MasterProtocol, SubProtocol) AS description,
    'T1046' AS mitre_mapping,
    4 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort) || ':' || MasterProtocol || ':' || SubProtocol)), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND Protocol = 'UDP'
    AND ServerToClientPacketCount <= 1
    AND ClientToServerDuration < 500
    AND MasterProtocol IN ('DNS', 'NTP', 'SSDP', 'DHCP', 'DHCPV6')
    AND SubProtocol != 'Unknown'
    AND SrcIp NOT IN ({excluded_ips_list}) -- Placeholder for global exclusion list (SYSLOG_IP, Management_IP)
GROUP BY
    SrcIp, DestIp, MasterProtocol, SubProtocol
HAVING
    count(DISTINCT DestPort) > 5
ORDER BY
    Unique_DestPorts_Scanned DESC
LIMIT 50;
```

We would add a cpp file to run the detections where they pull necessary data from the metadata and execute the query on the specified schedule

The intent is to allow us to publish new detections without the need for a software update and to support silent(monitor mode) where the query runs but does not create a detection that the customer sees in central. I think this requires us to set the monitor_mode field in the datalake when the results are sent to central. We should check how MDR_ops publishes and creates new SIGMA rules for detections.

