#include "./tox_p2prng.hpp"

// packets:
//
// init_with_hmac
//   - id
//   - peerlist (includes sender, determines fusion order)
//   - sender hmac
//
// hmac
//   - id
//   - hmac
//
// hmac_request
//   - id
//
// secret
//   - id
//   - secret (msg+k)
//
// secret_request
//   - id

enum PKG {
	INIT_WITH_HMAC,
	HMAC,
	HMAC_REQUEST,
	SECRET,
	SECRET_REQUEST,
};

ToxP2PRNG::ToxP2PRNG(
	ToxI& t,
	ToxEventProviderI& tep,
	ToxContactModel2& tcm
) : _t(t), _tep(tep), _tcm(tcm) {
	_tep.subscribe(this, Tox_Event_Type::TOX_EVENT_FRIEND_LOSSLESS_PACKET);
	_tep.subscribe(this, Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PACKET);
	_tep.subscribe(this, Tox_Event_Type::TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET);
}

ToxP2PRNG::~ToxP2PRNG(void) {
}

std::vector<uint8_t> ToxP2PRNG::newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) {
	return {};
}

std::vector<uint8_t> ToxP2PRNG::newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) {
	return {};
}

P2PRNG::State ToxP2PRNG::getSate(const ByteSpan id) {
	return P2PRNG::State::UNKNOWN;
}

ByteSpan ToxP2PRNG::getResult(const ByteSpan id) {
	return {};
}

bool ToxP2PRNG::handlePacket(
	Contact3Handle c,
	const uint8_t* data,
	const size_t data_size
) {
	if (data_size < 1) {
		return false; // waht
	}

	PKG pkg_type = static_cast<PKG>(data[0]);

	switch (pkg_type) {
		case PKG::INIT_WITH_HMAC:
			return parse_init_with_hmac(c, data+1, data_size-1);
		case PKG::HMAC:
			return parse_hmac(c, data+1, data_size-1);
		case PKG::HMAC_REQUEST:
			return parse_hmac_request(c, data+1, data_size-1);
		case PKG::SECRET:
			return parse_secret(c, data+1, data_size-1);
		case PKG::SECRET_REQUEST:
			return parse_secret_request(c, data+1, data_size-1);
		default:
			return false;
	}


	return false;
}

bool ToxP2PRNG::handleFriendPacket(
	const uint32_t friend_number,
	const uint8_t* data,
	const size_t data_size
) {
	auto c = _tcm.getContactFriend(friend_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, data, data_size);
}

bool ToxP2PRNG::handleGroupPacket(
	const uint32_t group_number,
	const uint32_t peer_number,
	const uint8_t* data,
	const size_t data_size,
	const bool /*_private*/
) {
	auto c = _tcm.getContactGroupPeer(group_number, peer_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, data, data_size);
}

bool ToxP2PRNG::parse_init_with_hmac(Contact3Handle c, const uint8_t* data, size_t data_size) {
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_hmac(Contact3Handle c, const uint8_t* data, size_t data_size) {
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_hmac_request(Contact3Handle c, const uint8_t* data, size_t data_size) {
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_secret(Contact3Handle c, const uint8_t* data, size_t data_size) {
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_secret_request(Contact3Handle c, const uint8_t* data, size_t data_size) {
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Friend_Lossless_Packet* e) {
	const auto friend_number = tox_event_friend_lossless_packet_get_friend_number(e);
	const uint8_t* data = tox_event_friend_lossless_packet_get_data(e);
	const auto data_length = tox_event_friend_lossless_packet_get_data_length(e);

	return handleFriendPacket(friend_number, data, data_length);
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Group_Custom_Packet* e) {
	const auto group_number = tox_event_group_custom_packet_get_group_number(e);
	const auto peer_number = tox_event_group_custom_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_packet_get_data(e);
	const auto data_length = tox_event_group_custom_packet_get_data_length(e);

	return handleGroupPacket(group_number, peer_number, data, data_length, false);
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) {
	const auto group_number = tox_event_group_custom_private_packet_get_group_number(e);
	const auto peer_number = tox_event_group_custom_private_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_private_packet_get_data(e);
	const auto data_length = tox_event_group_custom_private_packet_get_data_length(e);

	return handleGroupPacket(group_number, peer_number, data, data_length, true);
}

