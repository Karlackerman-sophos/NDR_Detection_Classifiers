#ifndef DETECTION_COMMON_HPP
#define DETECTION_COMMON_HPP

#include <string>
#include <vector>
#include <map>

struct detection_configuration_t {
    std::map<std::string, std::string> config_map;
};

struct LoadedDetectionRule {
    std::string id;
    std::string name;
    std::string description;
    bool enabled{ false };
    int frequency_seconds{ 86400 };
    int monitor_mode{ 1 };
    std::string mitre_attack_mapping;
    int severity_score_default{ 0 };
    std::string sql_query_template;
    std::string rule_dir_path;
    bool apply_global_ip_exclusions{ true };
};

#endif // DETECTION_COMMON_HPP
