/*
Name: Internal Host Recon - High Unique IP SYN Scan
Description:
  Detects an internal source IP performing a stealthy SYN scan against a high number of unique private IP addresses.
  This indicates active reconnaissance to discover live hosts, likely from a compromised system or unauthorized activity.
  Alerts on broad network mapping attempts.
MITRE ATT&CK Mapping:
  T1595.001 - Active Scanning: Scanning IP Blocks/Ranges: Directly relevant as it's scanning many unique IPs.
Severity Score: 4
Rationale:
  High confidence of active reconnaissance. Could be legitimate (e.g., poorly configured internal scanner), but warrants investigation.
  High unique IPs often points to deliberate scanning. Stealthy nature adds to suspicion. Could be a compromised host.
*/
SELECT
    'syn_scan' AS report_name,
    SrcIp,
    count(DISTINCT DestIp) AS Unique_DestIPs_Scanned,
    min(Timestamp) AS First_Scan_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} performed stealthy SYN scan against {} unique internal IPs. Reconnaissance suspected.', SrcIp, toString(count(DISTINCT DestIp))) AS description,
    'T1595.001' AS mitre_mapping,
    4 AS severity_score,
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
    AND SrcIp NOT IN ({excluded_ips_list}) -- Placeholder for global exclusion list (SYSLOG_IP, Management_IP)
GROUP BY
    SrcIp
HAVING
    count(DISTINCT DestIp) > 50
ORDER BY
    Unique_DestIPs_Scanned DESC
LIMIT 50; 
