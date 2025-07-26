#ifndef DETECTION_MANAGER_HPP
#define DETECTION_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <jansson.h> // For json_t

// Forward-declare the ClickHouse client class
class Client;

// A simple type definition for the configuration map
struct detection_configuration_t {
    std::map<std::string, std::string> config_map;
};

// Struct to hold all the parsed information for a single detection rule
struct LoadedDetectionRule {
    std::string id;
    std::string name;
    std::string description;
    bool enabled{ true };
    int frequency_seconds{ 0 };
    int monitor_mode{ 0 };
    std::string execution_device;
    std::string min_ndr_version;
    std::string mitre_attack_mapping;
    int severity_score_default{ 0 };
    bool apply_global_ip_exclusions{ true };
    std::string sql_query_template;
    std::string rule_dir_path;
};

// Manages the lifecycle of fetching, loading, running, and reporting on detection rules.
class DetectionManager {
public:
    // Constructor
    DetectionManager(detection_configuration_t* _config);

    // Destructor
    ~DetectionManager();

    // Initializes the manager
    bool Init();

    // Executes all enabled detection rules
    void RunAllDetections();

    // Prints a formatted summary table of all loaded rules
    void PrintRulesSummary();

    // Cleans up resources
    bool Cleanup();

    // Executes a single, specified rule
    void RunSingleRule(const LoadedDetectionRule& rule);

    // Returns a constant reference to the vector of loaded rules
    const std::vector<LoadedDetectionRule>& GetLoadedRules() const;

private:
    // Helper methods for internal logic
    bool setupGitRepository();
    bool discoverAndLoadRules();
    bool loadMetadataForRule(const std::string& metadata_json_path, LoadedDetectionRule& rule);
    std::string loadSqlQueryFile(const std::string& sql_file_path);
    std::string constructExcludedIpsList(const std::string& syslog_ip, const std::string& mgmt_ip);
    void replaceAll(std::string& str, const std::string& from, const std::string& to);

    // --- Member Variables ---
    detection_configuration_t* config;
    std::unique_ptr<Client> clickhouse_client;
    std::vector<LoadedDetectionRule> loaded_rules;
    std::string git_rules_base_path;
    std::string temp_git_repo_path;
}; // <-- A missing semicolon here is a very common cause for this error.

#endif // DETECTION_MANAGER_HPP