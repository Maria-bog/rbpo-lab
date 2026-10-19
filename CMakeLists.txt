cmake_minimum_required(VERSION 3.18)
project(rbpo_lab VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(ENABLE_ASAN "Instrument application and dependency" OFF)
if(ENABLE_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

# Change version AND hash together when updating the dependency.
set(XML_VERSION "2.11.5")
set(XML_SHA256 "3727b078c360ec69fa869de14bd6f75d7ee8d36987b071e6928d4720a28df3a6")
string(REGEX MATCH "^[0-9]+\\.[0-9]+" XML_SERIES "${XML_VERSION}")
include(FetchContent)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
foreach(feature PYTHON PROGRAMS TESTS ZLIB LZMA ICONV ICU HTTP FTP MODULES)
  set(LIBXML2_WITH_${feature} OFF CACHE BOOL "" FORCE)
endforeach()
FetchContent_Declare(libxml2
  URL "https://download.gnome.org/sources/libxml2/${XML_SERIES}/libxml2-${XML_VERSION}.tar.xz"
  URL_HASH "SHA256=${XML_SHA256}")
FetchContent_MakeAvailable(libxml2)

add_executable(rbpo_lab src/main.cpp)
target_link_libraries(rbpo_lab PRIVATE LibXml2::LibXml2)
target_compile_options(rbpo_lab PRIVATE -Wall -Wextra -Wpedantic)

# Declared direct-dependency SBOM, not a scanner's discovery result.
file(WRITE "${CMAKE_BINARY_DIR}/dependencies.cdx.json"
"{
  \"bomFormat\": \"CycloneDX\",
  \"specVersion\": \"1.4\",
  \"version\": 1,
  \"metadata\": {
    \"component\": {
      \"type\": \"application\", \"name\": \"rbpo-lab\",
      \"version\": \"1.0\", \"bom-ref\": \"rbpo-lab\"
    }
  },
  \"components\": [{
    \"type\": \"library\",
    \"name\": \"libxml2\",
    \"version\": \"${XML_VERSION}\",
    \"bom-ref\": \"libxml2\",
    \"purl\": \"pkg:generic/libxml2@${XML_VERSION}\",
    \"cpe\": \"cpe:2.3:a:xmlsoft:libxml2:${XML_VERSION}:*:*:*:*:*:*:*\",
    \"externalReferences\": [{
      \"type\": \"distribution\",
      \"url\": \"https://download.gnome.org/sources/libxml2/${XML_SERIES}/libxml2-${XML_VERSION}.tar.xz\",
      \"hashes\": [{\"alg\": \"SHA-256\", \"content\": \"${XML_SHA256}\"}]
    }]
  }],
  \"dependencies\": [
    {\"ref\": \"rbpo-lab\", \"dependsOn\": [\"libxml2\"]},
    {\"ref\": \"libxml2\", \"dependsOn\": []}
  ]
}
")