#pragma once

#include "./p2prng.hpp"

#include <solanaceae/tox_contacts/tox_contact_model2.hpp>

// implements P2PRNGI for tox
// both tox friends(1to1) aswell as tox ngc(NtoN) should be supported
class ToxP2PRNG : public P2PRNGI {
	ToxContactModel2& _tcm;

	public:
		ToxP2PRNG(ToxContactModel2& tcm);
		~ToxP2PRNG();

	public: // p2prng
		std::vector<uint8_t> newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) override;
		std::vector<uint8_t> newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) override;

		P2PRNG::State getSate(const ByteSpan id) override;
		ByteSpan getResult(const ByteSpan id) override;
};
