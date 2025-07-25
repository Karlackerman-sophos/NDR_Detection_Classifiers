/*
Name: Internal Host Recon - IP Protocol Scan
Description:
  Detects an internal source IP attempting to discover which IP protocols (e.g., TCP, UDP, ICMP, IGMP) are supported by target hosts
  by sending probes with many different IP protocol numbers.
MITRE ATT&CK Mapping:
  T1046 - Network Service Discovery: For finding services/protocols.
Severity Score: 4
Rationale:
  IP protocol scans are highly unusual in normal network traffic and are almost exclusively used for reconnaissance by security tools or attackers.
*/
SELECT
    'ip_protocol_scan' AS report_name,
    SrcIp,
    DestIp,
    count(DISTINCT Protocol) AS Unique_Protocols_Scanned,
    min(Timestamp) AS First_Scan_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} performed IP protocol scan against {} by probing {} unique protocols. Protocol discovery suspected.', SrcIp, DestIp, toString(count(DISTINCT Protocol))) AS description,
    'T1046' AS mitre_mapping,
    4 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(Protocol))), 1, 10), ', ') AS Sample_Dest_IP_Protocol_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND DestPort = 0
    AND ClientToServerPacketCount = 1
    AND ServerToClientPacketCount <= 1
    AND ClientToServerDuration < 500
    AND SrcIp NOT IN ({excluded_ips_list}) -- Placeholder for global exclusion list (SYSLOG_IP, Management_IP)
GROUP BY
    SrcIp, DestIp
HAVING
    count(DISTINCT Protocol) > 3
ORDER BY
    Unique_Protocols_Scanned DESC
LIMIT 50;
