# ==========================================================================
# PocketDNS - top-level project CMake file
#
# This is the ENTRY POINT of the whole build. It does almost nothing itself:
# it just pulls in ESP-IDF's build machinery and declares the project name.
# All the real work happens in the component CMakeLists (e.g. main/).
# ==========================================================================
cmake_minimum_required(VERSION 3.16)

# Pull in the ESP-IDF cmake project tooling. $ENV{IDF_PATH} is set when you
# run `. ./export.sh` (or `idf.py`), so this line "connects" us to the SDK.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# The project name becomes the firmware binary name: pocketdns.bin
project(pocketdns)
