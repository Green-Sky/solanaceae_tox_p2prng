cmake_minimum_required(VERSION 3.24 FATAL_ERROR)

# cmake setup begin
project(solanaceae_tox_p2prng)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(SOLANACEAE_TOX_P2PRNG_STANDALONE ON)
else()
	set(SOLANACEAE_TOX_P2PRNG_STANDALONE OFF)
endif()
message("II SOLANACEAE_TOX_P2PRNG_STANDALONE " ${SOLANACEAE_TOX_P2PRNG_STANDALONE})

option(SOLANACEAE_TOX_P2PRNG_BUILD_PLUGINS "Build the solanaceae_tox_p2prng plugins" ${SOLANACEAE_TOX_P2PRNG_STANDALONE})

if (SOLANACEAE_TOX_P2PRNG_STANDALONE)
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)

	# defaulting to debug mode, if not specified
	if(NOT CMAKE_BUILD_TYPE)
		set(CMAKE_BUILD_TYPE "Debug")
	endif()

	# setup my vim ycm :D
	set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

	# more paths
	set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
	set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

# external libs
add_subdirectory(./external EXCLUDE_FROM_ALL) # before increasing warn levels, sad :(

if (SOLANACEAE_TOX_P2PRNG_STANDALONE)
	set(CMAKE_CXX_EXTENSIONS OFF)

	# bump up warning levels appropriately for clang, gcc & msvc
	if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
		add_compile_options(
			-Wall -Wextra # Reasonable and standard
			-Wpedantic # Warn if non-standard C++ is used
			-Wunused # Warn on anything being unused
			#-Wconversion # Warn on type conversions that may lose data
			#-Wsign-conversion # Warn on sign conversions
			-Wshadow # Warn if a variable declaration shadows one from a parent context
		)

		if (NOT WIN32)
			#link_libraries(-fsanitize=address)
			#link_libraries(-fsanitize=address,undefined)
			#link_libraries(-fsanitize-address-use-after-scope)
			#link_libraries(-fsanitize=undefined)
		endif()
	elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")
		if (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
			string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		else()
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
		endif()
	endif()

endif()

# cmake setup end

add_subdirectory(./src)

if (SOLANACEAE_TOX_P2PRNG_BUILD_PLUGINS)
	add_subdirectory(./plugins)
endif()

