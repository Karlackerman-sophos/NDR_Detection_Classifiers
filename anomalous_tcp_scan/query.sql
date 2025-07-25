/*
Name: Internal Host Recon - Anomalous TCP Flag Scan
Description:
  Detects an internal source IP sending probes with highly unusual TCP flag combinations (e.g., FIN, NULL, Xmas, or pure ACK).
  This often indicates an advanced reconnaissance attempt designed to evade detection or map firewalls.
MITRE ATT&CK Mapping:
  T1595.002 - Active Scanning: Vulnerability Scanning: These flags are used to probe for services, potentially bypassing detection.
Severity Score: 5
Rationale:
  Extremely high confidence. These are highly specific and almost always malicious or from a dedicated security testing tool.
  The FP rate should be very low if configured correctly.
*/
SELECT
    'anomalous_tcp_scan' AS report_name,
    SrcIp,
    ClientToServerTcpFlags,
    count(DISTINCT DestIp) AS Unique_DestIPs_Probed,
    count(DISTINCT DestPort) AS Unique_DestPorts_Probed,
    count() AS Total_Probes,
    min(Timestamp) AS First_Probe,
    max(Timestamp) AS Last_Attempt,
    format('Src {} sent {} probes with anomalous TCP flags ({}). Evasion or advanced reconnaissance suspected.', SrcIp, toString(count()), toString(ClientToServerTcpFlags)) AS description,
    'T1595.002' AS mitre_mapping,
    5 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort))), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND ClientToServerPacketCount = 1
    AND ServerToClientPacketCount <= 1
    AND ClientToServerDuration < 500
    AND (
           ClientToServerTcpFlags = 1
        OR ClientToServerTcpFlags = 0
        OR ClientToServerTcpFlags = 41
        OR ClientToServerTcpFlags = 16
    )
GROUP BY
    SrcIp, ClientToServerTcpFlags
HAVING
    count(DISTINCT DestIp) > 10 OR count(DISTINCT DestPort) > 10
ORDER BY
    Total_Probes DESC
LIMIT 50;
