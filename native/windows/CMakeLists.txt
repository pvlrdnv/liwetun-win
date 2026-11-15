cmake_minimum_required(VERSION 3.14)
find_program(LIWETUN_CARGO cargo REQUIRED)
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|amd64|x86_64")
  message(FATAL_ERROR "LiWeTun native bridge currently qualifies only Windows x64")
endif()
get_filename_component(LIWETUN_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../trusttunnel_bridge" ABSOLUTE)
set(LIWETUN_CARGO_OUT "${CMAKE_CURRENT_BINARY_DIR}/cargo")
set(LIWETUN_RUST_LIB "${LIWETUN_CARGO_OUT}/x86_64-pc-windows-msvc/release/liwetun_native.lib")
add_custom_command(
  OUTPUT "${LIWETUN_RUST_LIB}"
  COMMAND "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${LIWETUN_CARGO_OUT}"
    "${LIWETUN_CARGO}" build --manifest-path "${LIWETUN_NATIVE_DIR}/Cargo.toml"
    --target x86_64-pc-windows-msvc --release --locked
  WORKING_DIRECTORY "${LIWETUN_NATIVE_DIR}"
  DEPENDS "${LIWETUN_NATIVE_DIR}/Cargo.toml" "${LIWETUN_NATIVE_DIR}/Cargo.lock"
    "${LIWETUN_NATIVE_DIR}/src/lib.rs" "${LIWETUN_NATIVE_DIR}/../../rust-toolchain.toml"
  VERBATIM
)
add_custom_target(liwetun_rust_build DEPENDS "${LIWETUN_RUST_LIB}")
add_library(liwetun_native STATIC IMPORTED GLOBAL)
set_target_properties(liwetun_native PROPERTIES IMPORTED_LOCATION "${LIWETUN_RUST_LIB}")
target_include_directories(liwetun_native INTERFACE "${LIWETUN_NATIVE_DIR}/include")
target_link_libraries(liwetun_native INTERFACE advapi32 bcrypt kernel32 ntdll userenv ws2_32)
add_dependencies(liwetun_native liwetun_rust_build)
