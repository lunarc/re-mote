cmake_minimum_required(VERSION 3.20)

project(re-mote VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

#find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets

# Tell CMake to use packages from vcpkg
set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
# For libssh specifically  
set(libssh_DIR "$ENV{VCPKG_ROOT}/vcpkg_installed/x64-windows/share/libssh" CACHE PATH "")

find_package(libssh CONFIG REQUIRED)
find_package(Qt6 COMPONENTS Widgets Network REQUIRED)

set(PROJECT_SOURCES
        ssh_client.h
        ssh_client.cpp
        ssh_port_forward.h
        ssh_port_forward.cpp
        forwarding_channel.h
        forwarding_channel.cpp
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        password_dialog.h
        password_dialog.cpp
        password_dialog.ui
        notebook_controller.h
        notebook_controller.cpp
        job_dialog.h
        job_dialog.cpp
        job_dialog.ui
)

    qt_add_executable(re-mote
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )

target_link_libraries(re-mote PRIVATE Qt6::Widgets Qt6::Network ssh)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.

set_target_properties(re-mote PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS re-mote
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_finalize_executable(re-mote)

set_target_properties(re-mote PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)

add_custom_command(TARGET re-mote POST_BUILD 
    COMMAND Qt6::windeployqt
    ARGS $<TARGET_FILE:re-mote>
)