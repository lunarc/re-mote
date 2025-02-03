cmake_minimum_required(VERSION 3.16)

project(qtssh VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

#find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets

find_package(libssh CONFIG REQUIRED)
find_package(Qt6 COMPONENTS Widgets Network REQUIRED)

set(PROJECT_SOURCES
        ssh_client.h
        ssh_client.cpp
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

    qt_add_executable(qtssh
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )

target_link_libraries(qtssh PRIVATE Qt6::Widgets Qt6::Network ssh)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.

set_target_properties(qtssh PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS qtssh
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_finalize_executable(qtssh)

set_target_properties(qtssh PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)

add_custom_command(TARGET qtssh POST_BUILD 
    COMMAND Qt6::windeployqt
    ARGS $<TARGET_FILE:qtssh>
)