#ifndef DETECTION_COMMON_HPP
#define DETECTION_COMMON_HPP

#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

struct detection_configuration_t {
    std::map<std::string, std::string> config_map;
};

struct LoadedDetectionRule {
    std::string id;
    std::string name;
    std::string description;
    bool enabled{ false };
    std::string type;
    int frequency_seconds{ 86400 };
    int monitor_mode{ 1 };
    std::string mitre_attack_mapping;
    int severity_score_default{ 0 };
    std::string sql_query_template;
    std::string rule_dir_path;
    bool apply_global_ip_exclusions{ true };
    std::string execution_device;
    std::string min_ndr_version;

    nlohmann::json raw_metadata;
};

#endif // DETECTION_COMMON_HPP
