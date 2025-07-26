/*
Name: Internal Host Recon - Discovery Protocol Abuse
Description:
  Identifies an internal source IP querying multiple unique hosts or a high volume of traffic related to typically benign discovery protocols
  (LLMNR, MDNS, SSDP, WSD, NATPMP, SLP).
  This can indicate an attacker attempting to enumerate internal hosts, services, or perform credential relay attacks.
MITRE ATT&CK Mapping:
  T1046 - Network Service Discovery: For finding services.
Severity Score: 5
Rationale:
  Abuse of these specific protocols is a very high-fidelity indicator of malicious internal reconnaissance,
  often a precursor to lateral movement and credential theft. Benign use typically involves low volume or specific applications.
*/
SELECT
    'discovery_protocol_abuse' AS report_name,
    SrcIp,
    MasterProtocol,
    SubProtocol,
    count(DISTINCT DestIp) AS Unique_DestIPs_Queried,
    count() AS Total_Queries,
    min(Timestamp) AS First_Query_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} performed a high volume of {} queries (Sub: {}) against {} unique internal IPs. Discovery protocol abuse suspected.', SrcIp, MasterProtocol, SubProtocol, toString(count(DISTINCT DestIp))) AS description,
    'T1046' AS mitre_mapping,
    5 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort) || ':' || MasterProtocol || ':' || SubProtocol)), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND Protocol = 'UDP'
    AND MasterProtocol IN ('LLMNR', 'MDNS', 'SSDP', 'WSD', 'NATPMP', 'SLP')
    AND DestIp IN ('224.0.0.251', '239.255.255.250', '224.0.0.252')
    AND SubProtocol != 'Unknown'
    AND SrcIp NOT IN ({excluded_ips_list}) -- Placeholder for global exclusion list (SYSLOG_IP, Management_IP)
GROUP BY
    SrcIp, MasterProtocol, SubProtocol
HAVING
    count(DISTINCT DestIp) > 5
    OR count() > 20
ORDER BY
    Total_Queries DESC
LIMIT 50;
