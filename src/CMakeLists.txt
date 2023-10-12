include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/lib source)

add_executable(smartdns ${source})

target_compile_options(smartdns PUBLIC -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing -funwind-tables -Wmissing-prototypes -Wshadow -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough)

if(${DEBUG})
target_compile_options(smartdns PUBLIC -g)
else()
target_compile_options(smartdns PUBLIC -O2)
endif()

if(DEFINED ${VER})
target_compile_options(smartdns PUBLIC -DSMARTDNS_VERION='${VER}')
endif()

target_compile_features(smartdns PUBLIC cxx_std_11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBASE_FILE_NAME='\"$(notdir  $<)\"'")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $(EXTRA_CFLAGS)")

if(${STATIC})
target_link_options(smartdns LINK_PUBLIC  -Wl,--whole-archive -Wl,--no-whole-archive -static)
endif()

target_link_libraries(smartdns LINK_PUBLIC ssl crypto pthread dl)

install(TARGETS smartdns
	RUNTIME DESTINATION "/usr/sbin"
)
