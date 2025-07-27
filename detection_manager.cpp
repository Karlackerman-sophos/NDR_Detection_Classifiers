#include "detection_manager.hpp"
#include <git2.h>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <functional>
#include <ctime>
#include <filesystem>
#include <utility>

// Use a type alias for convenience
using json = nlohmann::json;

// =========================================================================
// !!! DUMMY IMPLEMENTATIONS (FOR REALISTIC SIMULATION) !!!
// =========================================================================
#ifndef PRODUCTION_BUILD

class ClientOptions {
public:
    ClientOptions& SetHost(const std::string& h) { _host = h; return *this; }
    ClientOptions& SetUser(const std::string& u) { _user = u; return *this; }
    ClientOptions& SetPassword(const std::string& p) { _pass = p; return *this; }
    ClientOptions& SetPort(int p) { _port = p; return *this; }
    ClientOptions& SetDefaultDatabase(const std::string& d) { _db = d; return *this; }
private:
    std::string _host, _user, _pass, _db;
    int _port{ 0 };
};

// More flexible dummy column that holds a vector of strings
class ColumnString {
public:
    explicit ColumnString(std::vector<std::string> data) : data_(std::move(data)) {}
    const char* At(size_t row) const {
        return row < data_.size() ? data_[row].c_str() : "";
    }
private:
    std::vector<std::string> data_;
};

// More flexible dummy block that can be built dynamically
class Block {
public:
    size_t GetRowCount() const { return row_count_; }
    size_t GetColumnCount() const { return column_names_.size(); }
    std::string GetColumnName(size_t index) const {
        return index < column_names_.size() ? column_names_[index] : "";
    }
    std::unique_ptr<ColumnString> operator[](size_t index) const {
        // Create a new column with the same data for the simulation.
        return std::make_unique<ColumnString>(columns_data_[index]);
    }

    void AddColumn(const std::string& name, std::vector<std::string> data) {
        if (!data.empty()) {
            row_count_ = data.size();
        }
        column_names_.push_back(name);
        columns_data_.push_back(std::move(data));
    }
private:
    size_t row_count_{ 0 };
    std::vector<std::string> column_names_;
    std::vector<std::vector<std::string>> columns_data_;
};

// Factory function to create dummy data based on the rule ID
Block create_dummy_data_for_rule(const LoadedDetectionRule& rule) {
    Block block;
    // For each rule, add columns and data that match its SQL query's SELECT statement
    if (rule.id == "aggressive_scan") {
        block.AddColumn("report_name", { "aggressive_scan" });
        block.AddColumn("SrcIp", { "10.1.1.100" });
        block.AddColumn("Total_Unique_DestIPs", { "52" });
        block.AddColumn("Total_Unique_DestPorts", { "128" });
        block.AddColumn("Total_Attempts", { "1450" });
        block.AddColumn("description", { "Src 10.1.1.100 engaged in aggressive scanning..." });
    }
    else if (rule.id == "syn_scan") {
        block.AddColumn("report_name", { "syn_scan" });
        block.AddColumn("SrcIp", { "10.2.2.200" });
        block.AddColumn("Unique_Dest_IPs", { "123" });
        block.AddColumn("description", { "Src 10.2.2.200 performed a SYN scan..." });
    }
    else if (rule.id == "established_smbv1") {
        block.AddColumn("report_name", { "established_smbv1" });
        block.AddColumn("SrcIp", { "192.168.10.15" });
        block.AddColumn("DestIp", { "192.168.10.22" });
        block.AddColumn("description", { "Confirmed SMBv1 connection from 192.168.10.15 to 192.168.10.22" });
    }
    else {
        // Generic default for any other rule
        block.AddColumn("report_name", { rule.id });
        block.AddColumn("source_ip", { "172.16.0.10" });
        block.AddColumn("details", { "Generic simulated event." });
    }
    return block;
}

class Client {
public:
    Client(ClientOptions) {}
    // The Select method now accepts the rule to generate specific data
    void Select(const std::string& query, const LoadedDetectionRule& rule, std::function<void(const Block&)> cb) {
        Block data = create_dummy_data_for_rule(rule);
        cb(data);
    }
};

// =========================================================================
// !!! REAL LIBGIT2 IMPLEMENTATION !!!
// =========================================================================
namespace GitHelper {
    bool clone_or_pull_repo(const std::string& repo_url, const std::string& branch, const std::string& local_path) {
        std::cout << "Cloning " << repo_url << " branch '" << branch << "' to " << local_path << std::endl;
        git_repository* repo = nullptr;
        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
        clone_opts.checkout_branch = branch.c_str();
        int error = git_clone(&repo, repo_url.c_str(), local_path.c_str(), &clone_opts);
        if (error != 0) {
            const git_error* e = git_error_last();
            std::cerr << "Error cloning repository: " << error << " (" << e->klass << "): " << e->message << std::endl;
            if (repo) git_repository_free(repo);
            return false;
        }
        std::cout << "Successfully cloned repository." << std::endl;
        git_repository_free(repo);
        return true;
    }
}
#endif

DetectionManager::DetectionManager(detection_configuration_t* _config) : config(_config), clickhouse_client(nullptr) {
    auto it = config->config_map.find("GIT_RULES_PATH_VAR");
    git_rules_base_path = (it != config->config_map.end()) ? it->second : "detection_rules/";
}

DetectionManager::~DetectionManager() {}

bool DetectionManager::Init() {
    std::cout << "Initializing DetectionManager..." << std::endl;
    if (!setupGitRepository() || !discoverAndLoadRules()) return false;
    try {
        ClientOptions opts;
        opts.SetHost(config->config_map.at("DB_HOST_VAR")).SetUser(config->config_map.at("DB_USERNAME_VAR")).SetPassword(config->config_map.at("DB_PASSWORD_VAR")).SetPort(std::stoi(config->config_map.at("DB_PORT_VAR"))).SetDefaultDatabase(config->config_map.at("DB_NAME_VAR"));
        clickhouse_client = std::make_unique<Client>(opts);
    }
    catch (const std::exception& e) {
        std::cerr << "DB client initialization error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

const std::vector<LoadedDetectionRule>& DetectionManager::GetLoadedRules() const {
    return loaded_rules;
}

std::string wrap_text(const std::string& text, unsigned int line_width, const std::string& indent) {
    std::stringstream wrapped_text;
    std::stringstream word_stream(text);
    std::string word;

    if (word_stream >> word) {
        wrapped_text << word;
        size_t space_left = line_width - word.length();
        while (word_stream >> word) {
            if (space_left < word.length() + 1) {
                wrapped_text << '\n' << indent << word;
                space_left = line_width - word.length();
            }
            else {
                wrapped_text << ' ' << word;
                space_left -= (word.length() + 1);
            }
        }
    }
    return wrapped_text.str();
}

void DetectionManager::PrintRulesSummary() {
    std::cout << "\n--- Detection Rules Detailed Summary ---\n";
    const int label_width = 22;
    for (const auto& rule : loaded_rules) {
        std::cout << "\n" << std::string(80, '-') << "\n";
        std::cout << std::left << std::setw(label_width) << "ID:" << rule.id << "\n";
        std::cout << std::left << std::setw(label_width) << "Name:" << rule.name << "\n";
        std::cout << std::left << std::setw(label_width) << "Enabled:" << (rule.enabled ? "true" : "false") << "\n";
        std::cout << std::left << std::setw(label_width) << "Monitor Mode:" << rule.monitor_mode << "\n";
        std::cout << std::left << std::setw(label_width) << "Frequency (seconds):" << rule.frequency_seconds << "\n";
        std::cout << std::left << std::setw(label_width) << "Default Severity:" << rule.severity_score_default << "\n";
        std::cout << std::left << std::setw(label_width) << "MITRE Attack Mapping:" << rule.mitre_attack_mapping << "\n";
        std::cout << std::left << std::setw(label_width) << "Description:";
        std::cout << wrap_text(rule.description, 60, std::string(label_width, ' ')) << "\n";
    }
    std::cout << std::string(80, '-') << "\n";
    std::cout << "\nTotal rules loaded: " << loaded_rules.size() << "\n";
}

void DetectionManager::RunSingleRule(const LoadedDetectionRule& rule) {
    if (!rule.enabled) {
        printf("\n--- Skipping disabled rule: %s ---\n", rule.name.c_str());
        return;
    }

    std::cout << "\n" << std::string(80, '=') << "\n";
    printf("EXECUTING RULE: %s\n", rule.name.c_str());
    std::cout << std::string(80, '=') << "\n\n";

    std::cout << "1. Preparing Global Variables...\n";
    std::string excluded_ips = constructExcludedIpsList(config->config_map.at("SYSLOG_IP_STR"), config->config_map.at("MANAGEMENT_IP_STR"));
    std::cout << "   - {excluded_ips_list}: " << excluded_ips << "\n\n";

    std::cout << "2. Loading SQL template and substituting variables...\n";
    std::string final_sql = rule.sql_query_template;
    replaceAll(final_sql, "{excluded_ips_list}", excluded_ips);

    std::cout << "\n   --- Final SQL Query ---\n" << final_sql << "\n   -----------------------\n\n";

    std::cout << "3. Sending query to simulated ClickHouse client...\n";
    try {
        json report;
        clickhouse_client->Select(final_sql, rule, [&rule, &report](const Block& block) {
            report["detection_name"] = rule.name;
            report["severity"] = rule.severity_score_default;
            report["detection_context"] = json::array();
            for (size_t i = 0; i < block.GetRowCount(); ++i) {
                json item;
                for (size_t j = 0; j < block.GetColumnCount(); ++j) {
                    item[block.GetColumnName(j)] = block[j]->At(i);
                }
                report["detection_context"].push_back(item);
            }
            });

        std::cout << "\n4. Received simulated result:\n";
        std::cout << report.dump(2) << std::endl;

    }
    catch (const std::exception& e) {
        fprintf(stderr, "ERROR running rule %s: %s\n", rule.id.c_str(), e.what());
    }
}

void DetectionManager::RunAllDetections() {
    for (const auto& rule : loaded_rules) {
        RunSingleRule(rule);
    }
}

bool DetectionManager::Cleanup() {
    std::cout << "\nCleaning up..." << std::endl;
    clickhouse_client.reset();
    try {
        if (!temp_git_repo_path.empty() && std::filesystem::exists(temp_git_repo_path)) {
            std::filesystem::remove_all(temp_git_repo_path);
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Cleanup error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool DetectionManager::setupGitRepository() {
    try {
        temp_git_repo_path = (std::filesystem::temp_directory_path() / ("ndr_repo_" + std::to_string(std::time(nullptr)))).string();
        return GitHelper::clone_or_pull_repo(config->config_map.at("GIT_REPO_URL_VAR"), config->config_map.at("GIT_REPO_BRANCH_VAR"), temp_git_repo_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Git setup error: " << e.what() << std::endl;
        return false;
    }
}

bool DetectionManager::discoverAndLoadRules() {
    loaded_rules.clear();
    std::string rules_path = (std::filesystem::path(temp_git_repo_path) / git_rules_base_path).string();
    if (!std::filesystem::exists(rules_path)) {
        std::cerr << "Error: Rules directory does not exist after clone: " << rules_path << std::endl;
        return false;
    }
    std::cout << "Searching for rules in: " << rules_path << std::endl;
    for (const auto& entry : std::filesystem::directory_iterator(rules_path)) {
        if (entry.is_directory()) {
            LoadedDetectionRule rule;
            rule.id = entry.path().filename().string();
            if (loadMetadataForRule((entry.path() / "metadata.json").string(), rule)) {
                rule.sql_query_template = loadSqlQueryFile((entry.path() / "query.sql").string());
                if (!rule.sql_query_template.empty()) {
                    loaded_rules.push_back(rule);
                }
            }
        }
    }
    return !loaded_rules.empty();
}

bool DetectionManager::loadMetadataForRule(const std::string& path, LoadedDetectionRule& rule) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) { return false; }
        json data = json::parse(file);
        rule.name = data.value("name", "Unknown Name");
        rule.description = data.value("description", "");
        rule.enabled = data.value("enabled", true);
        rule.monitor_mode = data.value("monitor_mode", 0);
        rule.frequency_seconds = data.value("frequency_seconds", 3600);
        rule.severity_score_default = data.value("severity_score_default", 3);
        rule.mitre_attack_mapping = data.value("mitre_attack_mapping", "");
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading metadata from " << path << ": " << e.what() << std::endl;
        return false;
    }
}

std::string DetectionManager::loadSqlQueryFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void DetectionManager::replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    for (size_t pos = 0; (pos = str.find(from, pos)) != std::string::npos; pos += to.length()) {
        str.replace(pos, from.length(), to);
    }
}

std::string DetectionManager::constructExcludedIpsList(const std::string& syslog_ip, const std::string& mgmt_ip) {
    return "'" + mgmt_ip + "', '" + syslog_ip + "'";
}

#ifdef TEST_MAIN_BUILD
int main() {
    git_libgit2_init();

    detection_configuration_t config;
    config.config_map["DB_USERNAME_VAR"] = "test_user";
    config.config_map["DB_PASSWORD_VAR"] = "test_pass";
    config.config_map["DB_HOST_VAR"] = "localhost";
    config.config_map["DB_PORT_VAR"] = "9000";
    config.config_map["DB_NAME_VAR"] = "default";
    config.config_map["SYSLOG_IP_STR"] = "192.168.1.1";
    config.config_map["MANAGEMENT_IP_STR"] = "10.0.0.1";
    config.config_map["GIT_REPO_URL_VAR"] = "https://github.com/Karlackerman-sophos/NDR_Detection_Classifiers";
    config.config_map["GIT_REPO_BRANCH_VAR"] = "sophos-internal";
    config.config_map["GIT_RULES_PATH_VAR"] = "detection_rules/";

    DetectionManager manager(&config);

    if (manager.Init()) {
        manager.PrintRulesSummary();

        std::cout << "\n--- Now executing rules individually ---\n";
        for (const auto& rule : manager.GetLoadedRules()) {
            manager.RunSingleRule(rule);
        }
    }
    else {
        std::cerr << "Manager initialization failed." << std::endl;
        git_libgit2_shutdown();
        return 1;
    }

    if (!manager.Cleanup()) {
        git_libgit2_shutdown();
        return 1;
    }

    git_libgit2_shutdown();
    return 0;
}
#endif