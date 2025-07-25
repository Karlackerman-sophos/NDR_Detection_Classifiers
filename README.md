# NDR_Detection_Classifiers
A collection of detection queries and configuration data for use with Sophos NDR

I would like to add the ability for the NDR Sensor to run DDE detections from a git_repo so we do not have to create a cpp file for each new detection we add.

The repo would be structured similar to this:
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
│   ├── aggressive_multi_scan/       <-- New directory for Aggressive Multi-Target/Multi-Port Scan
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── discovery_protocol_abuse/    <-- New directory for Discovery Protocol Abuse
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── established_smbv1/           <-- New directory for Established SMBv1 Connection
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── full_connect_scan/           <-- New directory for Full-Connect Application Scan
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── ics_mgmt_scan/               <-- New directory for ICS/Management Protocol Scan
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── ip_protocol_scan/            <-- New directory for IP Protocol Scan
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── port_sweep/                  <-- New directory for Target Port Sweep
│   │   ├── metadata.json
│   │   └── query.sql
│   ├── smbv1_targeted_activity/     <-- New directory for SMBv1 Scan
│   │   ├── metadata.json
│   │   └── query.sql
│   └── udp_app_scan/                <-- New directory for UDP Application Scan
│       ├── metadata.json
│       └── query.sql
├── README.md

We would add a cpp file to run the detections where they pull necessary data from the metadata and execute the query on the specified schedule

The intent is to allow us to publish new detections without the need for a software update and to support silent(monitor mode) where the query runs but does not create a detection that the customer sees in central. I think this requires us to set the monitor_mode field in the datalake when the results are sent to central. We should check how MDR_ops publishes and creates new SIGMA rules for detections.
