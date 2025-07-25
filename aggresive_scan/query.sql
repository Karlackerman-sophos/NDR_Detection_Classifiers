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
    AND SrcIp NOT IN ({excluded_ips_list})
GROUP BY
    SrcIp
HAVING
    count(DISTINCT DestIp) > 20
    AND count(DISTINCT DestPort) > 5
    AND count() > 50
ORDER BY
    Total_Attempts DESC
LIMIT 50;
