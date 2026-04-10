add_executable(student_agent Src/echo_student.cpp)

target_link_libraries(student_agent PRIVATE 
    ArgusCommon 
    ${PCAP_LIB} 
    ${GLFW_LIBRARIES} 
    OpenGL::GL 
    Threads::Threads
)

# Deployment instruction: Put exe in 'bin' and config files in 'config'
install(TARGETS student_agent DESTINATION bin)
install(DIRECTORY config/ DESTINATION .)