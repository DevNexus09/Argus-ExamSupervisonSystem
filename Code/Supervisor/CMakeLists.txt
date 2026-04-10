add_executable(supervisor_app src/echo_supervisor.cpp src/dashboard.cpp)
target_include_directories(supervisor_app PRIVATE include)

target_link_libraries(supervisor_app PRIVATE 
    ArgusCommon 
    ${GLFW_LIBRARIES} 
    OpenGL::GL 
    Threads::Threads
)

# Deployment instruction: Put the exe in a 'bin' folder
install(TARGETS supervisor_app DESTINATION bin)