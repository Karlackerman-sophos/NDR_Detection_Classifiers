/*
Name: Internal Host Recon/Lateral Movement - SMBv1 Scan
Description:
  Detects attempts from an internal source IP to connect to or scan for SMBv1 services.
  SMBv1 is a deprecated and highly vulnerable protocol, and any active use from a non-authorized host is a critical security concern,
  often indicative of an adversary attempting lateral movement or exploitation (e.g., WannaCry, NotPetya).
MITRE ATT&CK Mapping:
  T1210 - Exploitation of Remote Services: If an actual attempt to exploit or use SMBv1 is made.
Severity Score: 5
Rationale:
  SMBv1 usage from an unapproved source is almost always malicious due to its severe known vulnerabilities. High confidence alert.
*/
SELECT
    'smbv1_scan' AS report_name,
    SrcIp,
    DestIp,
    MasterProtocol,
    SubProtocol,
    count() AS Total_SMBv1_Attempts,
    min(Timestamp) AS First_Attempt,
    max(Timestamp) AS Last_Attempt,
    format('Src {} made {} attempts to {} using highly vulnerable SMBv1 protocol. Possible exploitation or lateral movement.', SrcIp, toString(count()), DestIp) AS description,
    'T1210' AS mitre_mapping,
    5 AS severity_score,
    arrayStringConcat(arraySlice(arraySort(groupUniqArray(DestIp || ':' || toString(DestPort) || ':' || MasterProtocol || ':' || SubProtocol)), 1, 10), ', ') AS Sample_Dest_IP_Ports_List
FROM
    dragonfly.dragonflyClusterScoresJoin
WHERE
    DestIpCategory = 'private'
    AND Timestamp >= now() - toIntervalHour(1)
    AND (
        MasterProtocol IN ('SMBv1', 'NetBIOS')
        AND SubProtocol = 'SMBv1'
    )
GROUP BY
    SrcIp, DestIp, MasterProtocol, SubProtocol
HAVING
    count() > 50
ORDER BY
    Total_SMBv1_Attempts DESC
LIMIT 50;
