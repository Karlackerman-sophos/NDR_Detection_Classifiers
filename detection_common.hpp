#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory> // For std::unique_ptr

// --- Placeholder for ClickHouse Client Library Includes ---
// In a real project, this would be your actual ClickHouse C++ client SDK headers.
// For compilation without the real SDK, we'll provide minimal dummy classes in detection_manager.cpp.
class Client;
class ClientOptions;
class Block;
// Assuming ColumnString is part of Block access, e.g., block[j]->As<ColumnString>()
// class ColumnString;


// --- Placeholder for JSON Library Includes ---
// This example assumes 'jansson' library. If using another, adapt accordingly.
#include <jansson.h> // For json_t, json_object, json_array, etc.


// Configuration structure passed by the main framework
// This holds runtime-specific, global parameters
typedef struct {
    std::map<std::string, std::string> config_map;
    // Expected keys in config_map:
    // "DB_HOST_VAR", "DB_USERNAME_VAR", "DB_PASSWORD_VAR", "DB_PORT_VAR", "DB_NAME_VAR"
    // "TABLE_NAME_VAR" (e.g., "dragonfly")
    // "TIMESPAN_VAR" (e.g., "(Timestamp > '...' and Timestamp < '...')")
    // "SYSLOG_IP_STR", "MANAGEMENT_IP_STR"
    // "GIT_REPO_URL_VAR", "GIT_REPO_BRANCH_VAR", "GIT_RULES_PATH_VAR" (e.g., "detection-rules/")
    // "BATCH_ID" (for unique temp directories during execution)
} detection_configuration_t;

// Structure to hold details for a single loaded detection rule
struct LoadedDetectionRule {
    std::string id;                // e.g., "anomalous_tcp_scan"
    std::string name;              // e.g., "Internal Host Recon - Anomalous TCP Flag Scan"
    std::string description;
    bool enabled;                  // new flag: is this rule active?
    int frequency_seconds;         // e.g., 3600
    int monitor_mode;              // e.g., 1
    std::string execution_device;  // e.g., "NDR_Sensor"
    std::string min_ndr_version;   // e.g., "1.10.1-3063"
    std::string mitre_attack_mapping; // e.g., "T1595.002"
    int severity_score_default;    // e.g., 5
    bool apply_global_ip_exclusions; // new flag: whether to substitute excluded_ips_list

    std::string sql_query_template; // The raw SQL string with placeholders
    std::string rule_dir_path;      // Local path to the rule's directory in the cloned repo
};
