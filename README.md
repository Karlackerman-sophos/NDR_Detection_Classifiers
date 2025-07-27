# Sophos NDR Dynamic Detection Framework

This repository contains the C++ implementation of the Sophos NDR Dynamic Detection Framework. This framework enables the Sophos NDR sensor to automatically discover, load, and execute network threat detection rules defined in external SQL queries and metadata files, sourced from a Git repository.

---

## Table of Contents
1. [Purpose](#1-purpose)
2. [Architecture & Design](#2-architecture--design)
3. [File Structure](#3-file-structure)
    * [3.1 C++ Source Files](#31-c-source-files)
4. [Dependencies](#4-dependencies)
5. [Building the Framework](#5-building-the-framework)
6. [Configuration](#6-configuration)
7. [Adding and Updating Detection Rules](#7-adding-and-updating-detection-rules)
8. [Running the Framework](#8-running-the-framework)
9. [Key Considerations](#9-key-considerations)

---

## 1. Purpose

The primary goal of this framework is to decouple network threat detection logic from the NDR sensor's core binary. By externalizing detection rules into a Git-managed repository, security analysts can rapidly develop, deploy, and update detection content without requiring C++ code changes, recompilation, or redeployment of the NDR sensor software.

This enhances agility in responding to emerging threats and streamlines the content management lifecycle.

---

## 2. Architecture & Design

The framework is built around a **DetectionManager** class that orchestrates the entire process:

* **Git Integration**: On initialization, the `DetectionManager` clones or pulls the latest version of a specified Git repository that contains all detection rules.
* **Rule Discovery**: It scans a predefined path within the cloned repository (`detection-rules/`) to discover individual detection rule directories.
* **Dynamic Rule Loading**: For each discovered rule, it loads two key files:
    * `metadata.json`: Contains structured metadata about the rule (Name, ID, Description, Frequency, MITRE mapping, etc.).
    * `query.sql`: Contains the ClickHouse SQL query defining the detection logic.
* **Placeholder Substitution**: Before executing a SQL query, the `DetectionManager` performs string substitutions to inject runtime-specific values (e.g., globally excluded IP addresses) into the SQL.
* **Database Execution**: It executes the prepared SQL queries against a configured ClickHouse database.
* **Standardized Output**: Detection results from ClickHouse are processed into a standardized JSON format, combining rule metadata with query output for reporting.
* **Lifecycle Management**: Handles the setup, execution, and cleanup of resources (e.g., temporary Git clone directory).

---

## 3. File Structure

This section describes the C++ source files and the expected structure of the external Git repository.

### 3.1 C++ Source Files

* **detection_common.hpp**:
    * Defines common data structures used across the framework, such as `detection_configuration_t` (for global settings) and `LoadedDetectionRule` (to hold parsed rule metadata and SQL).
    * Includes necessary third-party library headers (e.g., `jansson.h` for JSON parsing, forward declarations for ClickHouse client).
* **detection_manager.hpp**:
    * Declares the `DetectionManager` class, which is the core orchestrator of the framework.
    * Defines the public interface (Init, RunAllDetections, Cleanup) and private helper methods.
* **detection_manager.cpp**:
    * Contains the implementation of the `DetectionManager` class.
    * Includes dummy implementations for `GitHelper` and `ClickHouse::Client` for compilation without actual libraries. These **MUST** be replaced with real library integrations for production use.

---

## 4. Dependencies

To build and run this framework, you will need:

* **C++ Compiler**: C++17 compliant (e.g., GCC 7+).
* **CMake**: For managing the build process (recommended).
* **ClickHouse C++ Client Library**: The official SDK for interacting with ClickHouse.
    * **Note**: The provided `detection_manager.cpp` contains dummy `Client` classes. You must integrate the real library.
* **Jansson Library**: For JSON parsing and generation.
    * **Note**: The provided code uses Jansson functions. Ensure it's installed and linked.
* **libgit2**: A portable C library for Git operations.
    * **Note**: The provided `detection_manager.cpp` contains a dummy `GitHelper` namespace. You must integrate the real `libgit2` calls.

---

## 5. Building the Framework

Assuming you are using CMake (recommended):

```bash
# Clone this C++ framework's repository
git clone <this_repo_url>
cd <this_repo_directory>

# Create a build directory
mkdir build && cd build

# Configure CMake (adjust paths to ClickHouse/Jansson/libgit2 as needed)
# Ensure you link against the actual libraries (-L<path> -l<lib_name>)
# You might need to adjust CMAKE_CXX_STANDARD if your compiler is older.
cmake .. -DCMAKE_BUILD_TYPE=Release -DTEST_MAIN_BUILD=ON # TEST_MAIN_BUILD for standalone test main

# Compile the project
make
```

---

## 6. Configuration

The framework is configured via a `detection_configuration_t` struct, which is a `std::map<std::string, std::string>`. This map is populated by a higher-level orchestrator process and passed to the `DetectionManager`.

Key configuration parameters include:

| Parameter Key          | Description                                                    | Example Value                                       |
| :--------------------- | :------------------------------------------------------------- | :-------------------------------------------------- |
| `DB_HOST_VAR`          | ClickHouse database host address                               | `localhost`                                         |
| `DB_USERNAME_VAR`      | ClickHouse database user                                       | `default`                                           |
| `DB_PASSWORD_VAR`      | ClickHouse database password                                   | `my_secret_password`                                |
| `DB_PORT_VAR`          | ClickHouse database port                                       | `9000`                                              |
| `DB_NAME_VAR`          | Default ClickHouse database name                               | `sophos_ndr_db`                                     |
| `TABLE_NAME_VAR`       | Common ClickHouse table name for network flow data             | `dragonfly.dragonflyClusterScoresJoin`              |
| `SYSLOG_IP_STR_VAR`    | IP address of the syslog server (for exclusion)                | `192.168.1.1`                                       |
| `MANAGEMENT_IP_STR_VAR`| IP address of the management interface (for exclusion)         | `10.0.0.1`                                          |
| `GIT_REPO_URL_VAR`     | URL of the Git repository containing detection rules           | `https://github.com/sophos/ndr-detection-rules.git` |
| `GIT_REPO_BRANCH_VAR`  | Branch of the Git repository to pull rules from                | `sophos_internal`                                   |
| `GIT_RULES_PATH_VAR`   | Path within the Git repository where rule directories reside   | `detection-rules/`                                  |
| `BATCH_ID_VAR`         | A unique ID for the current execution batch (for temp dir)     | `20250725_1120_batchA`                              |
| `TIMESPAN_VAR`         | Global time filter string (e.g., for Timestamp > X AND Timestamp < Y) | `(Timestamp > '1678886400' AND Timestamp < '1678890000')` |

---

## 7. Adding and Updating Detection Rules

Security analysts and content developers can add or update detection rules by:

* Creating a new directory under `your-detection-rules-repo/detection-rules/` (or the configured `GIT_RULES_PATH_VAR`). The directory name must be the unique ID of the new rule (e.g., `my_new_detection_rule/`).
* Creating `metadata.json` inside this new directory. This file defines the rule's name, description, frequency, execution device, etc., including an `"enabled": true/false` flag.
* Creating `query.sql` inside this new directory. This file contains the ClickHouse SQL query defining the detection logic.
    * Use placeholders like `{excluded_ips_list}` in your `WHERE` clause if you want the global IP exclusions to be applied.
    * Ensure the `SELECT` statement outputs the standard fields your system expects (e.g., `report_name`, `SrcIp`, `DestIp`, `description`, `mitre_mapping`, `severity_score`).
* Committing and Pushing these changes to the configured Git repository branch (`GIT_REPO_BRANCH_VAR`).

The NDR sensor running this framework will automatically pull these updates on its next scheduled run or initialization, without requiring a software rebuild or redeployment.

---

## 8. Running the Framework

In a production environment, this C++ framework (compiled as a shared library or integrated into a main executable) would be orchestrated by a higher-level process.

For testing purposes, a `main` function is provided within `detection_manager.cpp` (compiled when `TEST_MAIN_BUILD` is defined):

```bash
# From inside the build directory after `make`
./detection_manager_test # Or whatever your executable is named
```
This test executable will:
* Initialize the DetectionManager with dummy configuration.
* Simulate Git cloning and rule loading.
* Execute all loaded (and enabled) detection rules.
* Print the simulated detection reports to the console.
* Clean up temporary files.

---

## 9. Key Considerations

* **Production GitHelper & ClickHouse Client**: The dummy `GitHelper` and `ClickHouse::Client` implementations are for compilation and testing only. Replace them with robust, production-ready integrations of `libgit2` and the actual ClickHouse C++ client SDK.
* **Error Handling**: While improved, consider adding more granular logging, metrics, and alerting for rule failures or data processing issues in a production system.
* **Scheduling**: This framework executes all rules on `RunAllDetections()`. A production system would integrate with a scheduler (e.g., cron, Kubernetes CronJob, internal task scheduler) that calls `RunAllDetections()` at appropriate intervals, possibly per rule based on `frequency_seconds`.
* **Concurrency**: If multiple rules need to run in parallel, evaluate the thread-safety of the `ClickHouseClient` and implement appropriate concurrency controls (e.g., mutexes, thread pools, or separate client instances per concurrent task).
* **Schema Evolution**: Ensure the `dragonfly.dragonflyClusterScoresJoin` table schema remains compatible with the various detection queries. Any major schema changes will require coordinated updates to the SQL rules.
