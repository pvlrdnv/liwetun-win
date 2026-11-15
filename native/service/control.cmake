add_library(liwetun_control STATIC
  "${CMAKE_CURRENT_LIST_DIR}/security.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pipe_io.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/client.cpp")
target_include_directories(liwetun_control PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_compile_definitions(liwetun_control PUBLIC UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
target_compile_features(liwetun_control PUBLIC cxx_std_17)
target_link_libraries(liwetun_control PUBLIC advapi32 bcrypt crypt32 wintrust shell32 ole32)
