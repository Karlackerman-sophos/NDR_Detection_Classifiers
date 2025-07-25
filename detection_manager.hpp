#pragma once

#include "detection_common.hpp" // Includes common structs and JSON/Client placeholders
#include <filesystem> // For std::filesystem operations (C++17)
#include <stdexcept>  // For std::runtime_error, std::out_of_range, etc.

// Helper for Git operations (needs libgit2 implementation)
namespace GitHelper {
    bool clone_or_pull_repo(const std::string& repo_url, const std::string& branch, const std::string& local_path);
}

class DetectionManager {
public:
    DetectionManager(detection_configuration_t* _config);
    ~DetectionManager();

    // Initializes Git, clones repo, discovers and loads all rules, initializes DB client
    bool Init();

    // Executes all loaded and enabled detections
    // In a real system, this would be called by a scheduler at appropriate times.
    void RunAllDetections();

    // Cleans up temporary Git repository and ClickHouse client
    bool Cleanup();

private:
    detection_configuration_t* config;
    std::unique_ptr<Client> clickhouse_client; // Single client for the manager
    std::string temp_git_repo_path;            // Path to the local clone of the Git repo
    std::string git_rules_base_path;           // Path within the Git repo to the rule directories (e.g., "detection-rules/")

    std::vector<LoadedDetectionRule> loaded_rules; // Stores all discovered and loaded rules

    // Private helper methods for internal logic
    bool setupGitRepository();
    bool discoverAndLoadRules();
    bool loadMetadataForRule(const std::string& metadata_json_path, LoadedDetectionRule& rule);
    std::string loadSqlQueryFile(const std::string& sql_file_path);

    // Utility for string replacement
    void replaceAll(std::string& str, const std::string& from, const std::string& to);

    // Utility to construct excluded IP list string
    std::string constructExcludedIpsList(const std::string& syslog_ip, const std::string& mgmt_ip);
};
