# NDR Detection Rule Framework (Test Harness)

This project is a C++ application designed to act as a test harness for a set of security detection rules. It dynamically clones a Git repository containing the rules, parses their metadata and SQL queries, and simulates their execution in a detailed, step-by-step manner.

## Features

* Clones detection rules from a remote Git repository using **`libgit2`**.
* Parses rule metadata from `metadata.json` files using **`nlohmann/json`**.
* Displays a detailed, multi-line summary of all loaded rules.
* Simulates the execution of each rule with verbose output, showing variable substitution and the final SQL query.
* Uses **CMake** for building and **`vcpkg`** (in manifest mode) for dependency management.
* Configured for a **dynamically linked** build, with a post-build step to automatically copy required DLLs.

---
## Prerequisites

Before you begin, ensure you have the following installed:

1.  [**Git**](https://git-scm.com/downloads)
2.  [**Visual Studio 2022 Community Edition**](https://visualstudio.microsoft.com/vs/community/)
    * Make sure to install the **"Desktop development with C++"** workload, including the **CMake** components.
3.  [**vcpkg**](https://github.com/microsoft/vcpkg)
    * It is recommended to install `vcpkg` in a simple, non-system path like `C:\dev\vcpkg`.

---
## ⚙️ Setup and Build

1.  **Clone this Repository**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-folder>
    ```

2.  **Set up `vcpkg`**
    If you haven't already, run the one-time integration command to make Visual Studio aware of `vcpkg`.
    ```powershell
    # Navigate to your vcpkg installation directory
    cd C:\dev\vcpkg

    # Run the integration command
    .\vcpkg.exe integrate install
    ```

3.  **Open and Build in Visual Studio**
    * Open your project folder (`NDR_Detection_Classifiers`) directly in Visual Studio.
    * Visual Studio will automatically detect the **`vcpkg.json`** and **`CMakePresets.json`** files and configure the project. `vcpkg` will download and install the required dependencies.
    * Make sure the **`x64-debug`** preset is selected at the top.
    * Build the project by pressing **`F7`** or going to the menu **Build > Build All**.

---
## ▶️ Running the Application

After a successful build, you can run the test harness directly from Visual Studio:
1.  In the **Solution Explorer**, right-click on **`CMakeLists.txt`**.
2.  Select **"Set as Startup Item"**.
3.  Press the green **"Play"** button (or `F5`) to run the executable.

The build process automatically copies the necessary `.dll` files next to the executable, allowing it to run without any manual setup.

---
## Project File Structure

* **`vcpkg.json`**: Lists the project's external library dependencies.
* **`CMakeLists.txt`**: The main build script for CMake, including a post-build step to copy DLLs.
* **`CMakePresets.json`**: Configures the Visual Studio build environment.
* **`detection_common.hpp`**: Contains shared data structures.
* **`detection_manager.hpp`**: The main class declaration.
* **`detection_manager.cpp`**: The main class implementation and test `main()` function.