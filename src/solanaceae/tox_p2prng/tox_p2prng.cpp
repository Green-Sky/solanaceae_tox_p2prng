#include "./tox_p2prng.hpp"

#include <iostream>

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
	PKG pkg_type,
	const uint8_t* data,
	const size_t data_size
) {
	if (data_size < 1) {
		return false; // waht
	}

	// rn all are prefixed with ID, so here we go
	if (data_size < 32) {
		std::cerr << "TP2PRNG error: packet without id\n";
		return false;
	}

	ByteSpan id{data, 32};

	switch (pkg_type) {
		case PKG::INIT_WITH_HMAC:
			return parse_init_with_hmac(c, id, data+32, data_size-(32));
		case PKG::HMAC:
			return parse_hmac(c, id, data+32, data_size-(32));
		case PKG::HMAC_REQUEST:
			return parse_hmac_request(c, id, data+32, data_size-(32));
		case PKG::SECRET:
			return parse_secret(c, id, data+32, data_size-(32));
		case PKG::SECRET_REQUEST:
			return parse_secret_request(c, id, data+32, data_size-(32));
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
	// packet id + packet id + id
	if (data_size < 1+1+32) {
		return false;
	}

	if (data[0] != 0xB1) { // 177
		return false;
	}

	PKG tpr_pkg_type = static_cast<PKG>(data[1]);

	auto c = _tcm.getContactFriend(friend_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, tpr_pkg_type, data+2, data_size-2);
}

bool ToxP2PRNG::handleGroupPacket(
	const uint32_t group_number,
	const uint32_t peer_number,
	const uint8_t* data,
	const size_t data_size,
	const bool /*_private*/
) {
	// packet id + packet id + id
	if (data_size < 1+1+32) {
		return false;
	}

	if (data[0] != (0x80 | 38u)) { // 0xa6 / 166
		return false;
	}

	PKG tpr_pkg_type = static_cast<PKG>(data[1]);

	auto c = _tcm.getContactGroupPeer(group_number, peer_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, tpr_pkg_type, data+2, data_size-2);
}

bool ToxP2PRNG::parse_init_with_hmac(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size) {
	std::cerr << "TP2PRNG: got packet init_with_hmac\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_hmac(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size) {
	std::cerr << "TP2PRNG: got packet hmac\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_hmac_request(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size) {
	std::cerr << "TP2PRNG: got packet hmac_request\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_secret(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size) {
	std::cerr << "TP2PRNG: got packet secret\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::parse_secret_request(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size) {
	std::cerr << "TP2PRNG: got packet secret_request\n";
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

