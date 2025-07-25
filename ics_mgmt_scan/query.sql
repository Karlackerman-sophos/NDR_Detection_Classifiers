/*
Name: Internal Host Recon/Compromise - ICS/Management Protocol Scan
Description:
  Detects scanning or connection attempts targeting highly sensitive Industrial Control System (ICS) or out-of-band management protocols
  (IPMI, MMS, PROFINET_IO, EtherNet/IP, S7COMM, DNP3, IEC60870).
  Any activity related to these protocols from non-authorized sources is a critical security concern.
MITRE ATT&CK Mapping:
  T1046 - Network Service Discovery: For finding these specialized services.
Severity Score: 5
Rationale:
  Extremely high confidence. These protocols are not typically used by general IT devices for discovery,
  and any probing often indicates highly targeted malicious activity or a severe policy violation in environments where they are present.
*/
SELECT
    'ics_mgmt_scan' AS report_name,
    SrcIp,
    DestIp,
    MasterProtocol,
    SubProtocol,
    count() AS Total_Protocol_Attempts,
    min(Timestamp) AS First_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} made {} attempts to {} using sensitive protocol {} (Sub: {}). ICS/management reconnaissance or compromise suspected.', SrcIp, toString(Total_Protocol_Attempts), DestIp, MasterProtocol, SubProtocol) AS description,
    'T1046' AS mitre_mapping,
    5 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort) || ':' || MasterProtocol || ':' || SubProtocol)), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND (
        MasterProtocol IN ('IPMI', 'MMS', 'PROFINET_IO', 'ETHERNET_IP', 'S7COMM', 'DNP3', 'IEC60870')
        OR SubProtocol IN ('IPMI', 'MMS', 'PROFINET_IO', 'ETHERNET_IP', 'S7COMM', 'DNP3', 'IEC60870')
    )
    AND MasterProtocol != 'Unknown'
    AND SubProtocol != 'Unknown'
    AND SrcIp NOT IN ({excluded_ips_list}) -- Placeholder for global exclusion list (SYSLOG_IP, Management_IP)
GROUP BY
    SrcIp, DestIp, MasterProtocol, SubProtocol
HAVING
    count() > 1
ORDER BY
    Total_Protocol_Attempts DESC
LIMIT 50;
