# - Try to find the keyutils library
# Once done this will define
#  KEYUTILS_FOUND - System has libkeyutils
#  KEYUTILS_INCLUDE_DIRS - The libkeyutils include directories
#  KEYUTILS_LIBRARIES - The libraries needed to use libkeyutils

find_path(KEYUTILS_INCLUDE_DIR keyutils.h)

find_library(KEYUTILS_LIBRARY NAMES keyutils)

set(KEYUTILS_LIBRARIES ${KEYUTILS_LIBRARY})
set(KEYUTILS_INCLUDE_DIRS ${KEYUTILS_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set KEYUTILS_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(KEYUTILS DEFAULT_MSG KEYUTILS_LIBRARY KEYUTILS_INCLUDE_DIR)

mark_as_advanced(KEYUTILS_INCLUDE_DIR KEYUTILS_LIBRARY)

add_library(keyutils SHARED IMPORTED GLOBAL)
set_property(TARGET keyutils PROPERTY IMPORTED_LOCATION ${KEYUTILS_LIBRARY})
set_property(TARGET keyutils PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${KEYUTILS_INCLUDE_DIRS})

