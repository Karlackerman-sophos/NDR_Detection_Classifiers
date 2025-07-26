#include "detection_manager.hpp"
#include <git2.h>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <functional>
#include <ctime>
#include <filesystem>

// =========================================================================
// !!! DUMMY IMPLEMENTATIONS (Client Only) !!!
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
class ColumnString { public: const char* At(size_t) const { return "192.168.1.101"; } };
                           class Block {
                           public:
                               size_t GetRowCount() const { return 1; }
                               size_t GetColumnCount() const { return 2; }
                               std::string GetColumnName(size_t i) const { return (i == 0) ? "report_name" : "SrcIp"; }
                               std::unique_ptr<ColumnString> operator[](size_t) const { return std::make_unique<ColumnString>(); }
                           };
                           class Client {
                           public:
                               Client(ClientOptions) {}
                               void Select(const std::string&, std::function<void(const Block&)> cb) {
                                   cb(Block{});
                               }
                           };

                           // =========================================================================
                           // !!! REAL LIBGIT2 IMPLEMENTATION !!!
                           // =========================================================================
                           namespace GitHelper {
                               // NEW function to print available branches for debugging
                               void print_available_branches(git_repository* repo) {
                                   std::cout << "--- Available Branches ---" << std::endl;
                                   git_branch_iterator* it = nullptr;
                                   git_reference* ref = nullptr;
                                   git_branch_t type;
                                   const char* branch_name = nullptr;

                                   if (git_branch_iterator_new(&it, repo, GIT_BRANCH_REMOTE) != 0) {
                                       return;
                                   }

                                   while (git_branch_next(&ref, &type, it) == 0) {
                                       git_branch_name(&branch_name, ref);
                                       if (branch_name) {
                                           std::cout << branch_name << std::endl;
                                       }
                                       git_reference_free(ref);
                                   }
                                   git_branch_iterator_free(it);
                                   std::cout << "--------------------------" << std::endl;
                               }

                               bool clone_or_pull_repo(const std::string& repo_url, const std::string& branch, const std::string& local_path) {
                                   std::cout << "Cloning " << repo_url << " branch '" << branch << "' to " << local_path << std::endl;

                                   git_repository* repo = nullptr;
                                   git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
                                   clone_opts.checkout_branch = branch.c_str();

                                   int error = git_clone(&repo, repo_url.c_str(), local_path.c_str(), &clone_opts);

                                   if (error != 0) {
                                       const git_error* e = git_error_last();
                                       std::cerr << "Error cloning repository: " << error << " (" << e->klass << "): " << e->message << std::endl;

                                       // --- NEW DEBUGGING LOGIC ---
                                       // If the error was a not-found error, try to clone again without checkout to list branches
                                       if (e->klass == GIT_ERROR_REFERENCE) {
                                           std::cout << "Attempting to clone default branch to list available branches for debugging..." << std::endl;
                                           git_repository* debug_repo = nullptr;
                                           git_clone_options debug_opts = GIT_CLONE_OPTIONS_INIT; // Don't specify a branch
                                           if (git_clone(&debug_repo, repo_url.c_str(), (local_path + "_debug").c_str(), &debug_opts) == 0) {
                                               print_available_branches(debug_repo);
                                               git_repository_free(debug_repo);
                                               std::filesystem::remove_all(local_path + "_debug"); // Clean up debug clone
                                           }
                                           else {
                                               std::cerr << "Could not clone default branch for debugging." << std::endl;
                                           }
                                       }
                                       // --- END DEBUGGING LOGIC ---

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
                               git_rules_base_path = (it != config->config_map.end()) ? it->second : "detection-rules/";
                           }

                           DetectionManager::~DetectionManager() {}

                           bool DetectionManager::Init() {
                               std::cout << "Initializing DetectionManager..." << std::endl;
                               if (!setupGitRepository() || !discoverAndLoadRules()) {
                                   return false;
                               }
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

                           void DetectionManager::RunSingleRule(const LoadedDetectionRule& rule) {
                               if (!rule.enabled) {
                                   printf("\n--- Skipping disabled rule: %s ---\n", rule.name.c_str());
                                   return;
                               }
                               printf("\n--- Executing rule: %s ---\n", rule.name.c_str());
                               std::string query = rule.sql_query_template;
                               replaceAll(query, "{excluded_ips_list}", constructExcludedIpsList(config->config_map["SYSLOG_IP_STR"], config->config_map["MANAGEMENT_IP_STR"]));

                               json_t* report = json_object();
                               try {
                                   clickhouse_client->Select(query, [&rule, report](const Block& block) {
                                       json_object_set_new(report, "detection_name", json_string(rule.name.c_str()));
                                       json_object_set_new(report, "severity", json_integer(rule.severity_score_default));
                                       json_t* context = json_array();
                                       for (size_t i = 0; i < block.GetRowCount(); ++i) {
                                           json_t* item = json_object();
                                           for (size_t j = 0; j < block.GetColumnCount(); ++j) {
                                               json_object_set_new(item, block.GetColumnName(j).c_str(), json_string(block[j]->At(i)));
                                           }
                                           json_array_append_new(context, item);
                                       }
                                       json_object_set_new(report, "detection_context", context);
                                       });
                                   char* json_out = json_dumps(report, JSON_INDENT(2));
                                   if (json_out) {
                                       printf("Rule Output:\n%s\n", json_out);
                                       free(json_out);
                                   }
                               }
                               catch (const std::exception& e) {
                                   fprintf(stderr, "ERROR running rule %s: %s\n", rule.id.c_str(), e.what());
                               }
                               json_decref(report);
                           }

                           void DetectionManager::RunAllDetections() {
                               for (const auto& rule : loaded_rules) {
                                   RunSingleRule(rule);
                               }
                           }

                           void DetectionManager::PrintRulesSummary() {
                               std::cout << "\n--- Detection Rules Summary ---\n";
                               std::cout << std::left << std::setw(25) << "ID" << std::setw(30) << "Name" << "Enabled\n";
                               std::cout << std::string(65, '-') << "\n";
                               for (const auto& rule : loaded_rules) {
                                   std::cout << std::left << std::setw(25) << rule.id << std::setw(30) << rule.name << (rule.enabled ? "true" : "false") << "\n";
                               }
                               std::cout << "-----------------------------------------------------------------\n";
                               std::cout << loaded_rules.size() << " rules loaded.\n";
                           }

                           bool DetectionManager::Cleanup() {
                               std::cout << "\nCleaning up..." << std::endl;
                               clickhouse_client.reset();
                               try {
                                   if (!temp_git_repo_path.empty()) {
                                       if (std::filesystem::exists(temp_git_repo_path)) {
                                           std::filesystem::remove_all(temp_git_repo_path);
                                       }
                                       // Also remove the debug clone path if it exists
                                       if (std::filesystem::exists(temp_git_repo_path + "_debug")) {
                                           std::filesystem::remove_all(temp_git_repo_path + "_debug");
                                       }
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
                                   std::cerr << "Rules directory does not exist after clone: " << rules_path << std::endl;
                                   return false;
                               }
                               for (const auto& entry : std::filesystem::directory_iterator(rules_path)) {
                                   if (entry.is_directory()) {
                                       LoadedDetectionRule rule;
                                       rule.id = entry.path().filename().string();
                                       if (loadMetadataForRule((entry.path() / "metadata.json").string(), rule)) {
                                           rule.sql_query_template = loadSqlQueryFile((entry.path() / "query.sql").string());
                                           if (!rule.sql_query_template.empty()) loaded_rules.push_back(rule);
                                       }
                                   }
                               }
                               return !loaded_rules.empty();
                           }

                           bool DetectionManager::loadMetadataForRule(const std::string& path, LoadedDetectionRule& rule) {
                               std::ifstream file(path);
                               if (!file.is_open()) return false;
                               std::stringstream buffer;
                               buffer << file.rdbuf();
                               json_error_t err;
                               json_t* root = json_loads(buffer.str().c_str(), 0, &err);
                               if (!root) return false;

#define GET_JSON_STR(key, target) do{json_t*v=json_object_get(root,key);if(json_is_string(v))target=json_string_value(v);}while(0)
#define GET_JSON_INT(key, target) do{json_t*v=json_object_get(root,key);if(json_is_integer(v))target=json_integer_value(v);}while(0)
#define GET_JSON_BOOL(key, target) do{json_t*v=json_object_get(root,key);if(json_is_boolean(v))target=json_is_true(v);}while(0)

                               GET_JSON_STR("name", rule.name);
                               GET_JSON_BOOL("enabled", rule.enabled);
                               GET_JSON_INT("frequency_seconds", rule.frequency_seconds);
                               GET_JSON_INT("severity_score_default", rule.severity_score_default);

#undef GET_JSON_STR
#undef GET_JSON_INT
#undef GET_JSON_BOOL

                               json_decref(root);
                               return true;
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
                               // --- CORRECTED TYPO HERE ---
                               config.config_map["GIT_REPO_BRANCH_VAR"] = "sophos-internal";

                               config.config_map["GIT_RULES_PATH_VAR"] = "detection-rules/";

                               DetectionManager manager(&config);

                               if (manager.Init()) {
                                   manager.PrintRulesSummary();
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