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
    bool enabled{ true };
    int frequency_seconds{ 0 };
    int monitor_mode{ 0 };
    std::string mitre_attack_mapping;
    int severity_score_default{ 0 };
    std::string sql_query_template;
    std::string rule_dir_path;
};

#endif // DETECTION_COMMON_HPP