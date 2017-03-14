cmake_minimum_required(VERSION 3.5)
project(pam_e4crypt C)

#
# Dependencies
#
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

find_package(PAM REQUIRED)

find_package(Keyutils REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(UUID REQUIRED)

#
# Build
#

# modules on't start with "lib"
set(CMAKE_SHARED_MODULE_PREFIX "")

add_library(pam_e4crypt MODULE pam_e4crypt.c)
target_link_libraries(pam_e4crypt pam keyutils OpenSSL::Crypto uuid)

# install the module in the same place where all the other modules should be
# NOTE: we actually disrespect the install prefix here
if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    get_filename_component(CMAKE_INSTALL_LIBDIR ${PAM_LIBRARY} DIRECTORY)
endif()
install(TARGETS pam_e4crypt
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/security/"
)

