set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/imgui)

set(COMMON_SOURCES
    src/protocol.cpp
    src/trie.cpp
    src/hashtable.cpp
    src/priorityqueue.cpp
    src/huffman.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

add_library(ArgusCommon STATIC ${COMMON_SOURCES})

# This line ensures ArgusCommon inherits the GLFW include paths
target_link_libraries(ArgusCommon PUBLIC glfw)

target_include_directories(ArgusCommon PUBLIC 
    include 
    ${IMGUI_DIR} 
    ${IMGUI_DIR}/backends
)

# Linux specific fix
if(UNIX AND NOT APPLE)
    target_link_libraries(ArgusCommon PUBLIC ${CMAKE_DL_LIBS})
endif()