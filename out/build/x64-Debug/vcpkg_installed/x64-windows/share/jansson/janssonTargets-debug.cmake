#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "jansson::jansson" for configuration "Debug"
set_property(TARGET jansson::jansson APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(jansson::jansson PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/jansson_d.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/jansson_d.dll"
  )

list(APPEND _cmake_import_check_targets jansson::jansson )
list(APPEND _cmake_import_check_files_for_jansson::jansson "${_IMPORT_PREFIX}/debug/lib/jansson_d.lib" "${_IMPORT_PREFIX}/debug/bin/jansson_d.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
