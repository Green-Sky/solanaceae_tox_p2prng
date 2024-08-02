cmake_minimum_required(VERSION 3.24 FATAL_ERROR)

include(FetchContent)

if (NOT TARGET solanaceae_util)
	FetchContent_Declare(solanaceae_util
		GIT_REPOSITORY https://github.com/Green-Sky/solanaceae_util.git
		GIT_TAG master
	)
	FetchContent_MakeAvailable(solanaceae_util)
endif()

if (NOT TARGET solanaceae_plugin)
	FetchContent_Declare(solanaceae_plugin
		GIT_REPOSITORY https://github.com/Green-Sky/solanaceae_plugin.git
		GIT_TAG master
	)
	FetchContent_MakeAvailable(solanaceae_plugin)
endif()

if (NOT TARGET solanaceae_contact)
	FetchContent_Declare(solanaceae_contact
		GIT_REPOSITORY https://github.com/Green-Sky/solanaceae_contact.git
		GIT_TAG master
	)
	FetchContent_MakeAvailable(solanaceae_contact)
endif()

# only need the contact stuff
if (NOT TARGET solanaceae_tox_contacts)
	FetchContent_Declare(solanaceae_tox
		GIT_REPOSITORY https://github.com/Green-Sky/solanaceae_tox.git
		GIT_TAG master
	)
	FetchContent_MakeAvailable(solanaceae_tox)
endif()

if (NOT TARGET p2prng)
	FetchContent_Declare(p2prng
		GIT_REPOSITORY https://github.com/Green-Sky/p2prng.git
		GIT_TAG master
	)
	FetchContent_MakeAvailable(p2prng)
endif()

