/*
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
GROUP BY
    SrcIp, DestIp, MasterProtocol, SubProtocol
HAVING
    count(DISTINCT DestPort) > 5
ORDER BY
    Unique_DestPorts_Scanned DESC
LIMIT 50;
