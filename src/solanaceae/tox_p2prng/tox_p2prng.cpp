#include "./tox_p2prng.hpp"


ToxP2PRNG::ToxP2PRNG(ToxContactModel2& tcm) : _tcm(tcm) {
}

ToxP2PRNG::~ToxP2PRNG(void) {
}

std::vector<uint8_t> ToxP2PRNG::newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) {
	return {};
}

std::vector<uint8_t> newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) {
	return {};
}

