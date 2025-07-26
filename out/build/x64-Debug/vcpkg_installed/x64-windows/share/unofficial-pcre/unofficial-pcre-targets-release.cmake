#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "unofficial::pcre::pcre" for configuration "Release"
set_property(TARGET unofficial::pcre::pcre APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::pcre::pcre PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/pcre.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/pcre.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre "${_IMPORT_PREFIX}/lib/pcre.lib" "${_IMPORT_PREFIX}/bin/pcre.dll" )

# Import target "unofficial::pcre::pcreposix" for configuration "Release"
set_property(TARGET unofficial::pcre::pcreposix APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::pcre::pcreposix PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/pcreposix.lib"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "unofficial::pcre::pcre"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/pcreposix.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcreposix )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcreposix "${_IMPORT_PREFIX}/lib/pcreposix.lib" "${_IMPORT_PREFIX}/bin/pcreposix.dll" )

# Import target "unofficial::pcre::pcre16" for configuration "Release"
set_property(TARGET unofficial::pcre::pcre16 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::pcre::pcre16 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/pcre16.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/pcre16.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre16 )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre16 "${_IMPORT_PREFIX}/lib/pcre16.lib" "${_IMPORT_PREFIX}/bin/pcre16.dll" )

# Import target "unofficial::pcre::pcre32" for configuration "Release"
set_property(TARGET unofficial::pcre::pcre32 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::pcre::pcre32 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/pcre32.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/pcre32.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcre32 )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcre32 "${_IMPORT_PREFIX}/lib/pcre32.lib" "${_IMPORT_PREFIX}/bin/pcre32.dll" )

# Import target "unofficial::pcre::pcrecpp" for configuration "Release"
set_property(TARGET unofficial::pcre::pcrecpp APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(unofficial::pcre::pcrecpp PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/pcrecpp.lib"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "unofficial::pcre::pcre"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/pcrecpp.dll"
  )

list(APPEND _cmake_import_check_targets unofficial::pcre::pcrecpp )
list(APPEND _cmake_import_check_files_for_unofficial::pcre::pcrecpp "${_IMPORT_PREFIX}/lib/pcrecpp.lib" "${_IMPORT_PREFIX}/bin/pcrecpp.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
