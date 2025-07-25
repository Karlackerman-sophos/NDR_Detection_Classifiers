#include "detection_manager.hpp"
#include <cstdio>      // For printf
#include <iostream>    // For cout, cerr
#include <fstream>     // For file operations
#include <sstream>     // For stringstream
#include <functional>  // For std::function in dummy client callback
#include <ctime>       // For std::time in dummy batch_id

// =========================================================================
// !!! DUMMY IMPLEMENTATIONS FOR COMPILATION ONLY !!!
// REPLACE THESE WITH ACTUAL LIBRARY INTEGRATIONS (libgit2, ClickHouse SDK, etc.)
// =========================================================================

#ifndef PRODUCTION_BUILD // Use these dummy implementations only for testing/development without real libs

// Minimal Dummy ClickHouse Client Classes
// (As defined in previous step-through)
class ClientOptions {
public:
    ClientOptions& SetHost(const std::string& host) { _host = host; return *this; }
    ClientOptions& SetUser(const std::string& user) { _user = user; return *this; }
    ClientOptions& SetPassword(const std::string& pass) { _pass = pass; return *this; }
    ClientOptions& SetPort(int port) { _port = port; return *this; }
    ClientOptions& SetDefaultDatabase(const std::string& db) { _db = db; return *this; }
    std::string ToString() const { return "Host: " + _host + ", User: " + _user + ", Port: " + std::to_string(_port) + ", DB: " + _db; }
private:
    std::string _host, _user, _pass, _db;
    int _port;
};

// Dummy Block and ColumnString for simulating ClickHouse results
class ColumnString {
public:
    const char* At(size_t row) const {
        // Return dummy data. In real use, this would access actual column data.
        if (row == 0) return "dummy_value_row_0";
        if (row == 1) return "dummy_value_row_1";
        return "";
    }
};

class Block {
public:
    size_t GetRowCount() const { return 1; } // Simulate one row for dummy output
    size_t GetColumnCount() const { return 2; }
    std::string GetColumnName(size_t index) const {
        if (index == 0) return "report_name"; // Match a common output field
        if (index == 1) return "SrcIp";       // Match a common output field
        return "";
    }
    // Operator to mimic accessing columns. Returns a dummy ColumnString.
    std::unique_ptr<ColumnString> operator[](size_t index) const {
        return std::make_unique<ColumnString>();
    }
};

class Client {
public:
    Client(ClientOptions options) {
        std::cout << "Dummy ClickHouse Client created with options: " << options.ToString() << std::endl;
    }
    ~Client() {
        std::cout << "Dummy ClickHouse Client destroyed." << std::endl;
    }
    void Select(const std::string& query, std::function<void(const Block&)> callback) {
        std::cout << "Dummy ClickHouse Client executing query:\n" << query << std::endl;
        Block dummyBlock;
        callback(dummyBlock); // Call the callback with dummy data
    }
    void Execute(const std::string& query) {
        std::cout << "Dummy ClickHouse Client executing DDL/DML query:\n" << query << std::endl;
    }
};


// Dummy GitHelper Implementation (REPLACE WITH REAL LIBGIT2)
namespace GitHelper {
    bool clone_or_pull_repo(const std::string& repo_url, const std::string& branch, const std::string& local_path) {
        std::cout << "Simulating Git: Cloning/Pulling " << repo_url << " branch " << branch << " to " << local_path << std::endl;
        std::cout << "Creating dummy repo structure in: " << local_path << std::endl;

        // List of all rule IDs to create dummy files for
        std::vector<std::string> rule_ids = {
            "networkScan", "exfiltration", "anomalous_tcp_scan",
            "syn_scan", "smbv1_targeted_activity", "port_sweep",
            "discovery_protocol_abuse", "full_connect_scan", "ip_protocol_scan",
            "aggressive_multi_scan", "ics_mgmt_scan", "udp_app_scan",
            "kerberos_rc4_tgs", "dns_mining_pools", "db_api_scan" // Added db_api_scan
        };
        std::string base_rules_path = local_path + "/detection-rules/";
        std::filesystem::create_directories(base_rules_path);

        for (const auto& id : rule_ids) {
            std::string rule_dir = base_rules_path + id;
            std::filesystem::create_directories(rule_dir);

            // Dummy metadata.json content for all rules
            // Match the order and fields from the latest metadata JSON structure
            std::ofstream meta_file(rule_dir + "/metadata.json");
            meta_file << "{\n"
                      << "  \"id\": \"" << id << "\",\n"
                      << "  \"name\": \"" << id << " Detection (Dummy)\",\n"
                      << "  \"description\": \"This is a dummy description for the " << id << " rule.\",\n"
                      << "  \"enabled\": true,\n"
                      << "  \"frequency_seconds\": 3600,\n"
                      << "  \"monitor_mode\": 1,\n"
                      << "  \"execution_device\": \"NDR_Sensor\",\n"
                      << "  \"min_ndr_version\": \"1.10.1-3063\",\n"
                      << "  \"mitre_attack_mapping\": \"TXXX.XXX\",\n" // Generic dummy
                      << "  \"severity_score_default\": 3,\n"         // Generic dummy
                      << "  \"apply_global_ip_exclusions\": true\n"
                      << "}" << std::endl;
            meta_file.close();

            // Dummy query.sql content
            std::ofstream query_file(rule_dir + "/query.sql");
            query_file << "SELECT '" << id << "_report' AS report_name, SrcIp FROM dragonfly.dragonflyClusterScoresJoin "
                       << "WHERE Timestamp >= now() - toIntervalHour(1) AND SrcIp NOT IN ({excluded_ips_list}) LIMIT 1;" << std::endl;
            query_file.close();
        }
        return true;
    }
}

#endif // !PRODUCTION_BUILD

// =========================================================================
// END DUMMY IMPLEMENTATIONS
// =========================================================================


DetectionManager::DetectionManager(detection_configuration_t* _config)
    : config(_config), clickhouse_client(nullptr) {
    printf("DetectionManager constructed.\n");
    // Get base path for rules from config, default if not found
    auto it = config->config_map.find("GIT_RULES_PATH_VAR");
    git_rules_base_path = (it != config->config_map.end()) ? it->second : "detection-rules/";
}

DetectionManager::~DetectionManager() {
    // clickhouse_client is a unique_ptr, it will be deleted automatically.
    // temp_git_repo_path cleanup is explicitly in Cleanup() method.
}

bool DetectionManager::Init() {
    std::cout << "DetectionManager Init called." << std::endl;

    // 1. Setup Git Repository
    if (!setupGitRepository()) {
        std::cerr << "Failed to setup Git repository." << std::endl;
        return false;
    }

    // 2. Discover and Load All Rules
    if (!discoverAndLoadRules()) {
        std::cerr << "Failed to discover and load all detection rules." << std::endl;
        return false;
    }

    if (loaded_rules.empty()) {
        std::cerr << "No detection rules were loaded. Framework will not run any detections." << std::endl;
        return false;
    }

    // 3. Initialize ClickHouse Client
    try {
        int port = std::stoi(config->config_map.at("DB_PORT_VAR"));
        ClientOptions options;
        options.SetHost(config->config_map.at("DB_HOST_VAR"))
               .SetUser(config->config_map.at("DB_USERNAME_VAR"))
               .SetPassword(config->config_map.at("DB_PASSWORD_VAR"))
               .SetPort(port)
               .SetDefaultDatabase(config->config_map.at("DB_NAME_VAR"));
        clickhouse_client = std::make_unique<Client>(options);
    } catch (const std::out_of_range& e) {
        std::cerr << "Missing database configuration parameter: " << e.what() << std::endl;
        return false;
    } catch (const std::invalid_argument& e) {
        std::cerr << "Invalid database port number: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing ClickHouse client: " << e.what() << std::endl;
        return false;
    }

    return true;
}

void DetectionManager::RunAllDetections() {
    std::cout << "Running all discovered detections." << std::endl;

    // Prepare common, dynamic placeholders for all queries
    std::string excluded_ips_list_str = constructExcludedIpsList(
        config->config_map.at("SYSLOG_IP_STR"),
        config->config_map.at("MANAGEMENT_IP_STR")
    );
    std::string common_timespan_var = config->config_map.at("TIMESPAN_VAR"); // For rules that might use this specific placeholder

    for (const auto& rule : loaded_rules) {
        // Check if the rule is enabled before processing
        if (!rule.enabled) {
            printf("Skipping disabled rule: %s (ID: %s)\n", rule.name.c_str(), rule.id.c_str());
            continue;
        }

        printf("Executing rule: %s (ID: %s, Frequency: %d seconds)\n", rule.name.c_str(), rule.id.c_str(), rule.frequency_seconds);
        std::string final_sql_query = rule.sql_query_template;

        // Perform substitutions based on rule flags
        if (rule.apply_global_ip_exclusions) {
            replaceAll(final_sql_query, "{excluded_ips_list}", excluded_ips_list_str);
        } else {
            // If the rule explicitly says NOT to apply global exclusions,
            // ensure the placeholder is removed or replaced with an empty string
            // if it still exists in the SQL template.
            replaceAll(final_sql_query, "AND SrcIp NOT IN ({excluded_ips_list})", "");
            replaceAll(final_sql_query, "{excluded_ips_list}", "''"); // Or replace with something that doesn't break syntax
        }

        // Apply timespan substitution if the rule template includes it
        replaceAll(final_sql_query, "{timespan_filter}", common_timespan_var);


        // Execute the query
        json_t* report_root_json = json_object(); // Create a new JSON object for each report
        try {
            // The lambda captures `rule` (by const reference) and `report_root_json` (by pointer)
            clickhouse_client->Select(final_sql_query, [&rule, report_root_json](const Block& block) {
                // This callback processes results from ClickHouse and populates JSON
                if (block.GetRowCount() == 0) {
                    // Even if no rows, still report metadata if the rule ran
                    json_object_set_new(report_root_json, "detection_name", json_string(rule.name.c_str()));
                    json_object_set_new(report_root_json, "detection_id", json_string(rule.id.c_str()));
                    json_object_set_new(report_root_json, "description", json_string(rule.description.c_str()));
                    json_object_set_new(report_root_json, "frequency_seconds", json_integer(rule.frequency_seconds));
                    json_object_set_new(report_root_json, "monitor_mode", json_integer(rule.monitor_mode));
                    json_object_set_new(report_root_json, "min_ndr_version", json_string(rule.min_ndr_version.c_str()));
                    json_object_set_new(report_root_json, "execution_device", json_string(rule.execution_device.c_str()));
                    json_object_set_new(report_root_json, "enabled", json_boolean(rule.enabled));
                    json_object_set_new(report_root_json, "apply_global_ip_exclusions", json_boolean(rule.apply_global_ip_exclusions));
                    json_object_set_new(report_root_json, "mitre_attack_mapping", json_string(rule.mitre_attack_mapping.c_str()));
                    json_object_set_new(report_root_json, "severity_score_default", json_integer(rule.severity_score_default));

                    json_object_set_new(report_root_json, "detection_context_count", json_integer(0));
                    json_object_set_new(report_root_json, "detection_context", json_array()); // Empty array for no results
                    return;
                }

                // Populate the root JSON object with detection metadata
                json_object_set_new(report_root_json, "detection_name", json_string(rule.name.c_str()));
                json_object_set_new(report_root_json, "detection_id", json_string(rule.id.c_str()));
                json_object_set_new(report_root_json, "description", json_string(rule.description.c_str()));
                json_object_set_new(report_root_json, "frequency_seconds", json_integer(rule.frequency_seconds));
                json_object_set_new(report_root_json, "monitor_mode", json_integer(rule.monitor_mode));
                json_object_set_new(report_root_json, "min_ndr_version", json_string(rule.min_ndr_version.c_str()));
                json_object_set_new(report_root_json, "execution_device", json_string(rule.execution_device.c_str()));
                json_object_set_new(report_root_json, "enabled", json_boolean(rule.enabled));
                json_object_set_new(report_root_json, "apply_global_ip_exclusions", json_boolean(rule.apply_global_ip_exclusions));
                json_object_set_new(report_root_json, "mitre_attack_mapping", json_string(rule.mitre_attack_mapping.c_str()));
                json_object_set_new(report_root_json, "severity_score_default", json_integer(rule.severity_score_default));

                json_object_set_new(report_root_json, "detection_context_count", json_integer(block.GetRowCount()));

                json_t* context_arr = json_array();
                for (size_t i = 0; i < block.GetRowCount(); i++) {
                    json_t* context_obj = json_object();
                    for (size_t j = 0; j < block.GetColumnCount(); j++) {
                        // FIX: Use a named std::string temporary to avoid dangling pointer
                        std::string column_value = std::string(block[j]->At(i));
                        json_object_set_new(context_obj, block.GetColumnName(j).c_str(),
                                            json_string(column_value.c_str()));
                    }
                    json_array_append(context_arr, context_obj);
                }
                json_object_set(report_root_json, "detection_context", context_arr);
            });

            // At this point, report_root_json holds the results for 'rule'
            char* json_output = json_dumps(report_root_json, JSON_INDENT(2));
            if (json_output) {
                printf("Successfully ran rule %s. Output:\n%s\n", rule.id.c_str(), json_output);
                free(json_output); // Free string allocated by json_dumps
            } else {
                printf("Successfully ran rule %s, but failed to dump JSON output.\n", rule.id.c_str());
            }

        } catch (const std::exception& e) {
            fprintf(stderr, "ERROR running rule %s (ID: %s): %s\n", rule.name.c_str(), rule.id.c_str(), e.what());
        } catch (...) {
            fprintf(stderr, "UNKNOWN ERROR running rule %s (ID: %s)\n", rule.name.c_str(), rule.id.c_str());
        }
        json_decref(report_root_json); // Clean up json_t object for this report
    }
}

bool DetectionManager::Cleanup() {
    std::cout << "DetectionManager Cleanup called." << std::endl;

    clickhouse_client.reset(); // Release and delete the unique_ptr to ClickHouse client

    // Clean up the cloned Git repository
    try {
        if (!temp_git_repo_path.empty() && std::filesystem::exists(temp_git_repo_path)) {
            std::cout << "Cleaning up temporary Git repo: " << temp_git_repo_path << std::endl;
            std::filesystem::remove_all(temp_git_repo_path);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error during cleanup of temp directory " << temp_git_repo_path << ": " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool DetectionManager::setupGitRepository() {
    std::string git_repo_url = config->config_map.at("GIT_REPO_URL_VAR");
    std::string git_repo_branch = config->config_map.at("GIT_REPO_BRANCH_VAR");
    std::string batch_id = config->config_map.at("BATCH_ID");

    try {
        temp_git_repo_path = std::filesystem::temp_directory_path() / ("ndr_detection_repo_" + batch_id);
        if (std::filesystem::exists(temp_git_repo_path)) {
            std::filesystem::remove_all(temp_git_repo_path); // Clean previous run's clone
        }
        std::filesystem::create_directories(temp_git_repo_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating/cleaning temp directory " << temp_git_repo_path << ": " << e.what() << std::endl;
        return false;
    }

    return GitHelper::clone_or_pull_repo(git_repo_url, git_repo_branch, temp_git_repo_path);
}

bool DetectionManager::discoverAndLoadRules() {
    std::string rules_full_path = temp_git_repo_path + "/" + git_rules_base_path;
    if (!std::filesystem::exists(rules_full_path) || !std::filesystem::is_directory(rules_full_path)) {
        std::cerr << "Detection rules base path not found or is not a directory: " << rules_full_path << std::endl;
        return false;
    }

    loaded_rules.clear(); // Clear any previously loaded rules

    for (const auto& entry : std::filesystem::directory_iterator(rules_full_path)) {
        if (entry.is_directory()) {
            std::string rule_id = entry.path().filename().string(); // Directory name is the rule ID
            std::string rule_dir_path = entry.path().string();

            LoadedDetectionRule new_rule;
            new_rule.id = rule_id; // Set ID here, as it's used in error messages before metadata is loaded
            new_rule.rule_dir_path = rule_dir_path;

            std::string metadata_json_path = rule_dir_path + "/metadata.json";
            std::string query_sql_path = rule_dir_path + "/query.sql";

            if (!std::filesystem::exists(metadata_json_path)) {
                std::cerr << "Skipping rule " << rule_id << ": metadata.json not found at " << metadata_json_path << std::endl;
                continue;
            }
            if (!std::filesystem::exists(query_sql_path)) {
                std::cerr << "Skipping rule " << rule_id << ": query.sql not found at " << query_sql_path << std::endl;
                continue;
            }

            if (!loadMetadataForRule(metadata_json_path, new_rule)) {
                std::cerr << "Skipping rule " << rule_id << ": Failed to load metadata." << std::endl;
                continue;
            }

            new_rule.sql_query_template = loadSqlQueryFile(query_sql_path);
            if (new_rule.sql_query_template.empty()) {
                std::cerr << "Skipping rule " << rule_id << ": Failed to load SQL query." << std::endl;
                continue;
            }

            loaded_rules.push_back(new_rule);
            printf("Loaded rule: %s (ID: %s, Freq: %d)\n", new_rule.name.c_str(), new_rule.id.c_str(), new_rule.frequency_seconds);
        }
    }

    if (loaded_rules.empty()) {
        std::cerr << "WARNING: No detection rules found in " << rules_full_path << std::endl;
        return false; // Indicates no rules were loaded successfully
    }
    return true;
}

bool DetectionManager::loadMetadataForRule(const std::string& metadata_json_path, LoadedDetectionRule& rule) {
    std::ifstream file(metadata_json_path);
    if (!file.is_open()) {
        return false; // Error logged by caller
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_str = buffer.str();

    json_error_t error;
    json_t* root_json = json_loads(json_str.c_str(), 0, &error);
    if (!root_json) {
        std::cerr << "Error parsing JSON from " << metadata_json_path << ": " << error.text << std::endl;
        return false;
    }

    bool success = true;

    // Helper macro to safely get and assign JSON string values
    #define GET_JSON_STRING_FIELD(json_obj, key_name, target_var, metadata_path, success_flag) \
        do { \
            json_t* j_val = json_object_get(json_obj, key_name); \
            if (!j_val || !json_is_string(j_val)) { \
                std::cerr << "Metadata missing or invalid '" << key_name << "' in " << metadata_path << "\n"; \
                success_flag = false; \
            } else { \
                target_var = json_string_value(j_val); \
            } \
        } while(0)

    // Helper macro to safely get and assign JSON integer values
    #define GET_JSON_INT_FIELD(json_obj, key_name, target_var, metadata_path, success_flag) \
        do { \
            json_t* j_val = json_object_get(json_obj, key_name); \
            if (!j_val || !json_is_integer(j_val)) { \
                std::cerr << "Metadata missing or invalid '" << key_name << "' in " << metadata_path << "\n"; \
                success_flag = false; \
            } else { \
                target_var = json_integer_value(j_val); \
            } \
        } while(0)

    // Helper macro to safely get and assign JSON boolean values
    #define GET_JSON_BOOL_FIELD(json_obj, key_name, target_var, metadata_path, success_flag) \
        do { \
            json_t* j_val = json_object_get(json_obj, key_name); \
            if (!j_val || !json_is_boolean(j_val)) { \
                std::cerr << "Metadata missing or invalid '" << key_name << "' in " << metadata_path << "\n"; \
                success_flag = false; \
            } else { \
                target_var = json_is_true(j_val); \
            } \
        } while(0)


    // Extract fields using macros for robustness and consistency
    // Note: rule.id is already set by discoverAndLoadRules based on directory name
    GET_JSON_STRING_FIELD(root_json, "name", rule.name, metadata_json_path, success);
    GET_JSON_STRING_FIELD(root_json, "description", rule.description, metadata_json_path, success);
    GET_JSON_BOOL_FIELD(root_json, "enabled", rule.enabled, metadata_json_path, success);
    GET_JSON_INT_FIELD(root_json, "frequency_seconds", rule.frequency_seconds, metadata_json_path, success);
    GET_JSON_INT_FIELD(root_json, "monitor_mode", rule.monitor_mode, metadata_json_path, success);
    GET_JSON_STRING_FIELD(root_json, "execution_device", rule.execution_device, metadata_json_path, success);
    GET_JSON_STRING_FIELD(root_json, "min_ndr_version", rule.min_ndr_version, metadata_json_path, success);
    GET_JSON_STRING_FIELD(root_json, "mitre_attack_mapping", rule.mitre_attack_mapping, metadata_json_path, success);
    GET_JSON_INT_FIELD(root_json, "severity_score_default", rule.severity_score_default, metadata_json_path, success);
    GET_JSON_BOOL_FIELD(root_json, "apply_global_ip_exclusions", rule.apply_global_ip_exclusions, metadata_json_path, success);

    json_decref(root_json);
    return success;
    #undef GET_JSON_STRING_FIELD
    #undef GET_JSON_INT_FIELD
    #undef GET_JSON_BOOL_FIELD
}

std::string DetectionManager::loadSqlQueryFile(const std::string& sql_file_path) {
    std::ifstream file(sql_file_path);
    if (!file.is_open()) {
        // Error already logged by caller (discoverAndLoadRules)
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void DetectionManager::replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' contains 'from'
    }
}

std::string DetectionManager::constructExcludedIpsList(const std::string& syslog_ip, const std::string& mgmt_ip) {
    std::stringstream ss;
    // Always start with mgmt_ip
    ss << "('" << mgmt_ip;
    // Add syslog_ip if it's not empty and different from mgmt_ip
    if (!syslog_ip.empty() && syslog_ip != mgmt_ip) {
        ss << "', '" << syslog_ip << "')";
    } else {
        ss << "')"; // Close the parenthesis if only mgmt_ip or if syslog_ip is same/empty
    }
    return ss.str();
}


// --- Main function for testing (should be in a separate test_main.cpp) ---
#ifdef TEST_MAIN_BUILD // Define this macro in your build system to compile the main function

int main(int argc, char* argv[]) {
    // Dummy configuration provided by the "framework"
    detection_configuration_t config;
    config.config_map["DB_USERNAME_VAR"] = "test_user";
    config.config_map["DB_PASSWORD_VAR"] = "test_pass";
    config.config_map["DB_HOST_VAR"] = "localhost";
    config.config_map["DB_PORT_VAR"] = "9000";
    config.config_map["DB_NAME_VAR"] = "default";
    config.config_map["TABLE_NAME_VAR"] = "dragonfly"; // Common table name
    config.config_map["SYSLOG_IP_STR"] = "192.168.1.1";
    config.config_map["MANAGEMENT_IP_STR"] = "10.0.0.1";
    config.config_map["BATCH_ID"] = "current_run_" + std::to_string(std::time(nullptr)); // Unique ID for temp dir

    // Git repo details for the runner to clone/pull rules from
    config.config_map["GIT_REPO_URL_VAR"] = "https://github.com/dummy/rules.git"; // Dummy URL
    config.config_map["GIT_REPO_BRANCH_VAR"] = "main";
    config.config_map["GIT_RULES_PATH_VAR"] = "detection-rules/";

    // Dummy timespan filter string (might be used by some rules)
    config.config_map["TIMESPAN_VAR"] = "(Timestamp > '2025-07-24 16:00:00' AND Timestamp < '2025-07-24 17:00:00')";

    DetectionManager manager(&config);

    if (manager.Init()) {
        manager.RunAllDetections();
    } else {
        std::cerr << "DetectionManager initialization failed. Aborting." << std::endl;
        return 1;
    }

    if (!manager.Cleanup()) {
        std::cerr << "DetectionManager cleanup failed." << std::endl;
        return 1;
    }

    return 0;
}
#endif // TEST_MAIN_BUILD
