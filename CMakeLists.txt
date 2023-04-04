cmake_minimum_required(VERSION 3.1)



# Necessary when compiling against lower OS X versions, however, only change the CMAKE_OSX_DEPLOYMENT_TARGET
# Should be before project() according to documentation
if(0)
    set(CMAKE_OSX_SYSROOT /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/)
    set(CMAKE_OSX_DEPLOYMENT_TARGET 10.7)
endif()

project(OSX_SSL_VPN_Client)

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

set(project_dir ${CMAKE_CURRENT_SOURCE_DIR})

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${project_dir}/build/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${project_dir}/build/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${project_dir}/build/lib")


# Add compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99") #-Werror #-O0 -g

set(DEBUG 0)

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

if(LINUX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
endif()






# Source files used when building the library
set(SOURCE_FILES
        vpn.c
        vpn.h
        config.c
        config.h
        hdlc.c
        hdlc.h
        ppp.c
        ppp.h
        ppp_queue.c
        ppp_queue.h
        ssl.c
        ssl.h
        socket.c
        socket.h
        log.c
        log.h
        definitions.h
        utils.c
        utils.h
        mem.c mem.h)


# Source files used when building the executable
set(EXECUTABLE_SOURCE_FILES
        ${SOURCE_FILES}
        main.c)

# Add a target to build a library version
add_library(OSX_SSL_VPN STATIC ${SOURCE_FILES})

# Add a target to build an executable
add_executable(OSX_SSL_VPN_Client ${EXECUTABLE_SOURCE_FILES})


find_package(PkgConfig REQUIRED)


#Note the hard-coded OpenSSL version!
#This is to exclude the OpenSSL version that is pre-installed in OS X.
#Update as necessary...
#Tip: install http://brew.sh
#then; brew install openssl
#check your openssl version:
#pkg-config --modversion openssl
#If pkg-config reports version less than 1, try:
#brew link --force openssl
pkg_search_module(OPENSSL REQUIRED openssl>=1.0)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
    message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIRS}")
    message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    target_link_libraries(OSX_SSL_VPN_Client ${OPENSSL_LIBRARIES})
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
    message(STATUS "Could not find Openssl")
endif()


# Link threading support


find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(PUBLIC OSX_SSL_VPN_Client "-pthread")
endif()

if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(OSX_SSL_VPN_Client "${CMAKE_THREAD_LIBS_INIT} -lutil")
endif()







