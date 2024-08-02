#pragma once

#include <solanaceae/contact/contact_model3.hpp>
#include <solanaceae/util/span.hpp>

#include <cstdint>
#include <vector>

// general p2prng interface
struct P2PRNGI {
	// returns unique id, you can then use when listen to events
	// chooses peers depending on C, if C is a group it (tries?) to use everyone?
	virtual std::vector<uint8_t> newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) = 0;
	// manually tell it which peers to use
	virtual std::vector<uint8_t> newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) = 0;

	// TODO: events
};
