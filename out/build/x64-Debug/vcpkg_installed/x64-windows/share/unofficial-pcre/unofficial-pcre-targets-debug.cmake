#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "unofficial::pcre::pcre" for configuration "Debug"
set_property(TARGET unofficial::pcre::pcre APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::pcre::pcre PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/pcred.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/pcred.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre "${_IMPORT_PREFIX}/debug/lib/pcred.lib" "${_IMPORT_PREFIX}/debug/bin/pcred.dll" )

# Import target "unofficial::pcre::pcreposix" for configuration "Debug"
set_property(TARGET unofficial::pcre::pcreposix APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::pcre::pcreposix PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/pcreposixd.lib"
  IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG "unofficial::pcre::pcre"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/pcreposixd.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcreposix )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcreposix "${_IMPORT_PREFIX}/debug/lib/pcreposixd.lib" "${_IMPORT_PREFIX}/debug/bin/pcreposixd.dll" )

# Import target "unofficial::pcre::pcre16" for configuration "Debug"
set_property(TARGET unofficial::pcre::pcre16 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::pcre::pcre16 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/pcre16d.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/pcre16d.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre16 )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre16 "${_IMPORT_PREFIX}/debug/lib/pcre16d.lib" "${_IMPORT_PREFIX}/debug/bin/pcre16d.dll" )

# Import target "unofficial::pcre::pcre32" for configuration "Debug"
set_property(TARGET unofficial::pcre::pcre32 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::pcre::pcre32 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/pcre32d.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/pcre32d.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre32 )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre32 "${_IMPORT_PREFIX}/debug/lib/pcre32d.lib" "${_IMPORT_PREFIX}/debug/bin/pcre32d.dll" )

# Import target "unofficial::pcre::pcrecpp" for configuration "Debug"
set_property(TARGET unofficial::pcre::pcrecpp APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(unofficial::pcre::pcrecpp PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/pcrecppd.lib"
  IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG "unofficial::pcre::pcre"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/pcrecppd.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcrecpp )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcrecpp "${_IMPORT_PREFIX}/debug/lib/pcrecppd.lib" "${_IMPORT_PREFIX}/debug/bin/pcrecppd.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
