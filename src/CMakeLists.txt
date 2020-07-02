set (mlx5_regex_src mlx5_regex.c)

set(CMAKE_C_FLAGS "-std=gnu99")

# Make build flags compiler specific
if (CMAKE_COMPILER_IS_GNUCC)
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set (CMAKE_C_FLAGS "-D_REETRANT -ggdb -fPIC -Wall -Wextra -pedantic -O0")
	elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
		set (CMAKE_C_FLAGS "-D_REETRANT -DNDEBUG -fPIC -Wall -Wextra -pedantic -O3")
	endif ()
endif (CMAKE_COMPILER_IS_GNUCC)

add_executable (mlx-regex ${mlx5_regex_src})
target_link_libraries(mlx-regex mlx5 ibverbs)

# The rule to install daemon binary
install (TARGETS mlx-regex
	RUNTIME
	DESTINATION bin)
