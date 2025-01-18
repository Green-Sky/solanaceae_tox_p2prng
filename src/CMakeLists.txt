cmake_minimum_required(VERSION 3.10...3.24 FATAL_ERROR)

project(solanaceae)

add_library(solanaceae_tox_p2prng
	./solanaceae/tox_p2prng/p2prng.hpp
	./solanaceae/tox_p2prng/tox_p2prng.hpp
	./solanaceae/tox_p2prng/tox_p2prng.cpp
)

target_include_directories(solanaceae_tox_p2prng PUBLIC .)
target_compile_features(solanaceae_tox_p2prng PUBLIC cxx_std_17)
target_link_libraries(solanaceae_tox_p2prng PUBLIC
	solanaceae_util
	solanaceae_tox_contacts
	p2prng
)

########################################

