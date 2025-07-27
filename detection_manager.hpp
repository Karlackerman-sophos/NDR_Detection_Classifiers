#ifndef DETECTION_MANAGER_HPP
#define DETECTION_MANAGER_HPP

#include "detection_common.hpp"
#include <memory>

class Client; // Forward-declaration

class DetectionManager {
public:
    DetectionManager(detection_configuration_t* _config);
    ~DetectionManager();
    bool Init();
    void RunAllDetections();
    void PrintRulesSummary();
    bool Cleanup();
    void RunSingleRule(const LoadedDetectionRule& rule);
    const std::vector<LoadedDetectionRule>& GetLoadedRules() const;

private:
    bool setupGitRepository();
    bool discoverAndLoadRules();
    bool loadMetadataForRule(const std::string& metadata_json_path, LoadedDetectionRule& rule);
    std::string loadSqlQueryFile(const std::string& sql_file_path);
    std::string constructExcludedIpsList(const std::string& syslog_ip, const std::string& mgmt_ip);
    void replaceAll(std::string& str, const std::string& from, const std::string& to);

    detection_configuration_t* config;
    std::unique_ptr<Client> clickhouse_client;
    std::vector<LoadedDetectionRule> loaded_rules;
    std::string git_rules_base_path;
    std::string temp_git_repo_path;
};

#endif // DETECTION_MANAGER_HPP