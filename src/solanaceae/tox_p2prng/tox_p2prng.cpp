#include "./tox_p2prng.hpp"

#include <solanaceae/contact/components.hpp>
#include <solanaceae/tox_contacts/components.hpp>
#include <solanaceae/toxcore/tox_interface.hpp>

#include <iostream>
#include <vector>

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

#define TOX_PKG_ID_FRIEND 0xB1
#define TOX_PKG_ID_GROUP 0xa6

void ToxP2PRNG::RngState::fillInitalStatePreamble(const ByteSpan id) {
	// id
	// res = id
	inital_state_preamble = static_cast<std::vector<uint8_t>>(id);

	for (const auto c : contacts) {
		if (!c.any_of<Contact::Components::ToxFriendPersistent, Contact::Components::ToxGroupPeerPersistent>()) {
			inital_state_preamble.clear();
			return;
		}

		if (const auto* tfp = c.try_get<Contact::Components::ToxFriendPersistent>(); tfp != nullptr) {
			inital_state_preamble.insert(inital_state_preamble.cend(), tfp->key.data.cbegin(), tfp->key.data.cend());
			continue;
		}

		if (const auto* tgpp = c.try_get<Contact::Components::ToxGroupPeerPersistent>(); tgpp != nullptr) {
			inital_state_preamble.insert(inital_state_preamble.cend(), tgpp->peer_key.data.cbegin(), tgpp->peer_key.data.cend());
			continue;
		}
	}
}


void ToxP2PRNG::RngState::genFinalResult(void) {
	if (contacts.size() < 2) {
		return;
	}

	if (hmacs.size() < contacts.size()) {
		return;
	}

	if (secrets.size() < contacts.size()) {
		return;
	}

	// val

	if (inital_state.empty()) {
		return;
	}

	if (inital_state_preamble.empty()) {
		return;
	}

	final_result.resize(P2PRNG_COMBINE_LEN);

	{ // fist secret
		const auto& fs = secrets.at(contacts.front());
		if (p2prng_combine_init(final_result.data(), fs.data(), fs.size()) != 0) {
			final_result.clear();
			return;
		}
	}

	for (size_t i = 1; i < contacts.size(); i++) {
		const auto& s = secrets.at(contacts.at(i));
		if (p2prng_combine_update(final_result.data(), final_result.data(), s.data(), s.size()) != 0) {
			final_result.clear();
			return;
		}
	}

	// finally, add in is
	// hmmm copy, meh, we could do preamble and app is in seperate updates, which changes the algo, but should be fine
	{
		std::vector<uint8_t> full_is = inital_state_preamble;
		full_is.insert(full_is.cend(), inital_state.cbegin(), inital_state.cend());

		if (p2prng_combine_update(final_result.data(), final_result.data(), full_is.data(), full_is.size()) != 0) {
			final_result.clear();
			return;
		}
	}
	// we done
}

P2PRNG::State ToxP2PRNG::RngState::getState(void) const {
	//DONE, // rng is done, event contains full rng
	if (!final_result.empty()) {
		return P2PRNG::DONE;
	}

	//SECRET, // got a secret (phase start will be denoted by own, secrets received before we have all hmacs get queued up)
	if (hmacs.size() == contacts.size()) {
		return P2PRNG::SECRET;
	}

	//HMAC, // got a hmac (phase start will be denoted by the initiators hmac)
	if (!hmacs.empty()) {
		return P2PRNG::HMAC;
	}

	//INIT, // inital params (incoming or outgoing?)
	if (!inital_state.empty() && !inital_state_preamble.empty()) {
		return P2PRNG::INIT;
	}

	return P2PRNG::UNKNOWN;
}

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
	ByteSpan data
) {
	if (data.size < 1) {
		return false; // waht
	}

	// rn all are prefixed with ID, so here we go
	if (data.size < 32) {
		std::cerr << "TP2PRNG error: packet without id\n";
		return false;
	}

	ByteSpan id{data.ptr, 32};

	switch (pkg_type) {
		case PKG::INIT_WITH_HMAC:
			return handle_init_with_hmac(c, id, {data.ptr+32, data.size-(32)});
		case PKG::HMAC:
			return handle_hmac(c, id, {data.ptr+32, data.size-(32)});
		case PKG::HMAC_REQUEST:
			return handle_hmac_request(c, id, {data.ptr+32, data.size-(32)});
		case PKG::SECRET:
			return handle_secret(c, id, {data.ptr+32, data.size-(32)});
		case PKG::SECRET_REQUEST:
			return handle_secret_request(c, id, {data.ptr+32, data.size-(32)});
		default:
			return false;
	}

	return false;
}

bool ToxP2PRNG::handleFriendPacket(
	const uint32_t friend_number,
	ByteSpan data
) {
	// packet id + packet id + id
	if (data.size < 1+1+32) {
		return false;
	}

	if (data[0] != TOX_PKG_ID_FRIEND) {
		return false;
	}

	PKG tpr_pkg_type = static_cast<PKG>(data[1]);

	auto c = _tcm.getContactFriend(friend_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, tpr_pkg_type, {data.ptr+2, data.size-2});
}

bool ToxP2PRNG::handleGroupPacket(
	const uint32_t group_number,
	const uint32_t peer_number,
	ByteSpan data,
	const bool /*_private*/
) {
	// packet id + packet id + id
	if (data.size < 1+1+32) {
		return false;
	}

	if (data[0] != TOX_PKG_ID_GROUP) {
		return false;
	}

	PKG tpr_pkg_type = static_cast<PKG>(data[1]);

	auto c = _tcm.getContactGroupPeer(group_number, peer_number);
	if (!static_cast<bool>(c)) {
		return false;
	}

	return handlePacket(c, tpr_pkg_type, {data.ptr+2, data.size-2});
}

bool ToxP2PRNG::handle_init_with_hmac(Contact3Handle c, ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet INIT_WITH_HMAC\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::handle_hmac(Contact3Handle c, ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet HMAC\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::handle_hmac_request(Contact3Handle c, ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet HMAC_REQUEST\n";

	if (!data.empty()) {
		std::cerr << "TP2PRNG warning: HMAC_REQUEST pkg has extra data!\n";
	}

	const auto* rng_state = getRngSate(c, id);
	if (rng_state == nullptr) {
		return false;
	}

	return false;
}

bool ToxP2PRNG::handle_secret(Contact3Handle c, ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet SECRET\n";
	size_t curser = 0;

	return false;
}

bool ToxP2PRNG::handle_secret_request(Contact3Handle c, ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet SECRET_REQUEST\n";

	if (!data.empty()) {
		std::cerr << "TP2PRNG warning: SECRET_REQUEST pkg has extra data!\n";
	}

	const auto* rng_state = getRngSate(c, id);
	if (rng_state == nullptr) {
		return false;
	}

	// can only request secret if secret or done state
	if (const auto current_state = rng_state->getState(); !(current_state == P2PRNG::SECRET || current_state == P2PRNG::DONE)) {
		return false;
	}

	// find self contact
	// TODO: accel
	// TODO: do TagSelfStrong over contacts instead?? probably. maybe additionally
	Contact3Handle self;
	if (c.all_of<Contact::Components::Self>()) {
		self = Contact3Handle{*c.registry(), c.get<Contact::Components::Self>().self};
	} else if (c.all_of<Contact::Components::Parent>()) {
		Contact3Handle parent = {*c.registry(), c.get<Contact::Components::Parent>().parent};
		if (static_cast<bool>(parent) && parent.all_of<Contact::Components::Self>()) {
			self = Contact3Handle{*c.registry(), parent.get<Contact::Components::Self>().self};
		}
	}

	if (!static_cast<bool>(self)) {
		std::cerr << "TP2PRNG error: failed to look up self\n";
		return false;
	}

	auto self_secret_it = rng_state->secrets.find(self);
	if (self_secret_it == rng_state->secrets.cend()) {
		// hmmmmmmmmmm this bad
		std::cerr << "hmmmmmmmmmm this bad\n";
		return false;
	}

	// TODO: queue these instead
	// SEND secret to c
	send_secret(c, id, ByteSpan{self_secret_it->second});

	return true;
}

static std::tuple<std::vector<uint8_t>, const Contact::Components::ToxFriendEphemeral*, const Contact::Components::ToxGroupPeerEphemeral*> prepSendPkgWithID(Contact3Handle c, ToxP2PRNG::PKG pkg_type, ByteSpan id) {
	std::vector<uint8_t> pkg;

	// determine friend or group (meh)
	const auto* tfe = c.try_get<Contact::Components::ToxFriendEphemeral>();
	const auto* tgpe = c.try_get<Contact::Components::ToxGroupPeerEphemeral>();
	if (tfe != nullptr) {
		pkg.push_back(TOX_PKG_ID_FRIEND);
	} else if (tgpe != nullptr) {
		pkg.push_back(TOX_PKG_ID_GROUP);
	} else {
		return {};
	}
	pkg.push_back(static_cast<uint8_t>(pkg_type));

	// pack packet
	//   - id
	pkg.insert(pkg.cend(), id.cbegin(), id.cend());

	return {pkg, tfe, tgpe};
}

static bool sendToxPrivatePacket(
	ToxI& t,
	const Contact::Components::ToxFriendEphemeral* tfe,
	const Contact::Components::ToxGroupPeerEphemeral* tgpe,
	const std::vector<uint8_t>& pkg
) {
	// send to friend or group peer
	if (tfe != nullptr) {
		return
			t.toxFriendSendLosslessPacket(
				tfe->friend_number,
				pkg
			) == TOX_ERR_FRIEND_CUSTOM_PACKET_OK
		;
	} else if (tgpe != nullptr) {
		return
			t.toxGroupSendCustomPrivatePacket(
				tgpe->group_number, tgpe->peer_number,
				true,
				pkg
			) == TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK
		;
	}

	return false;
}

bool ToxP2PRNG::send_hmac(Contact3Handle c, ByteSpan id, const ByteSpan hmac) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::HMAC, id);
	if (pkg.empty()) {
		return false;
	}

	//   - hmac
	pkg.insert(pkg.cend(), hmac.cbegin(), hmac.cend());

	return false;
}

bool ToxP2PRNG::send_hmac_request(Contact3Handle c, ByteSpan id) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::HMAC_REQUEST, id);
	if (pkg.empty()) {
		return false;
	}

	return sendToxPrivatePacket(_t, tfe, tgpe, pkg);
}

bool ToxP2PRNG::send_secret(Contact3Handle c, ByteSpan id, const ByteSpan secret) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::SECRET, id);
	if (pkg.empty()) {
		return false;
	}

	//   - secret (msg+k)
	pkg.insert(pkg.cend(), secret.cbegin(), secret.cend());

	return sendToxPrivatePacket(_t, tfe, tgpe, pkg);
}

bool ToxP2PRNG::send_secret_request(Contact3Handle c, ByteSpan id) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::SECRET_REQUEST, id);
	if (pkg.empty()) {
		return false;
	}

	return sendToxPrivatePacket(_t, tfe, tgpe, pkg);
}

ToxP2PRNG::RngState* ToxP2PRNG::getRngSate(Contact3Handle c, ByteSpan id_bytes) {
	if (id_bytes.size != ID{}.size()) {
		return nullptr;
	}

	ID r_id{};
	{ // building the id is very annoying, should have not used array?
		// TODO: provide custom comperator ?
		for (size_t i = 0; i < r_id.size(); i++) {
			r_id[i] = id_bytes[i];
		}
	}

	const auto find_it = _global_map.find(r_id);
	if (find_it == _global_map.cend()) {
		return nullptr;
	}

	const auto find_c = std::find(find_it->second.contacts.cbegin(), find_it->second.contacts.cend(), c);
	if (find_c == find_it->second.contacts.cend()) {
		// id exists, but peer looking into id is not participating, so we block the request
		return nullptr;
	}

	return &find_it->second;
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Friend_Lossless_Packet* e) {
	const auto friend_number = tox_event_friend_lossless_packet_get_friend_number(e);
	const uint8_t* data = tox_event_friend_lossless_packet_get_data(e);
	const auto data_length = tox_event_friend_lossless_packet_get_data_length(e);

	return handleFriendPacket(friend_number, {data, data_length});
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Group_Custom_Packet* e) {
	const auto group_number = tox_event_group_custom_packet_get_group_number(e);
	const auto peer_number = tox_event_group_custom_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_packet_get_data(e);
	const auto data_length = tox_event_group_custom_packet_get_data_length(e);

	return handleGroupPacket(group_number, peer_number, {data, data_length}, false);
}

bool ToxP2PRNG::onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) {
	const auto group_number = tox_event_group_custom_private_packet_get_group_number(e);
	const auto peer_number = tox_event_group_custom_private_packet_get_peer_id(e);
	const uint8_t* data = tox_event_group_custom_private_packet_get_data(e);
	const auto data_length = tox_event_group_custom_private_packet_get_data_length(e);

	return handleGroupPacket(group_number, peer_number, {data, data_length}, true);
}

