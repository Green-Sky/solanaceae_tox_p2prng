#include "./tox_p2prng.hpp"

#include <solanaceae/contact/components.hpp>
#include <solanaceae/tox_contacts/components.hpp>
#include <solanaceae/toxcore/tox_interface.hpp>

#include <iostream>
#include <vector>
#include <utility>

// https://soundcloud.com/deadcrxw/glom-glass-deadcrow-flip-free-download

// packets:
//
// init_with_hmac
//   - id
//   - peerlist (includes sender, determines fusion order)
//   - sender hmac
//   - is
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

Contact3Handle ToxP2PRNG::RngState::getSelf(void) const {
	for (auto c : contacts) {
		if (c.all_of<Contact::Components::TagSelfStrong>()) {
			return c;
		}
	}

	return {};
}

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

void ToxP2PRNG::checkHaveAllHMACs(RngState* rng_state, const ByteSpan id) {
	if (rng_state == nullptr) {
		return;
	}

	if (rng_state->hmacs.size() != rng_state->contacts.size()) {
		// dont have all hmacs yet
		return;
	}
	// have all hmacs !

	// now we send out our secret and collect secrets
	// we should also validate any secret that already is in storage

	// validate existing (self should be good)
	std::vector<Contact3> bad_secrets;
	for (const auto& [pre_c, secret] : rng_state->secrets) {
		const auto& pre_hmac = rng_state->hmacs.at(pre_c);
		if (p2prng_auth_verify(secret.data()+P2PRNG_LEN, pre_hmac.data(), secret.data(), P2PRNG_LEN) != 0) {
			// bad secret
			std::cerr
				<< "########################################\n"
				<< "TP2PRNG error: bad secret, validation failed!\n"
				<< "########################################\n"
			;
			bad_secrets.push_back(pre_c);

			dispatch(
				P2PRNG_Event::val_error,
				P2PRNG::Events::ValError{
					id,
					pre_c,
				}
			);
		}
	}
	for (const auto bad_c : bad_secrets) {
		rng_state->secrets.erase(bad_c);
	}

	// find self contact
	Contact3Handle self = rng_state->getSelf();
	if (!static_cast<bool>(self)) {
		std::cerr << "TP2PRNG error: failed to look up self\n";
		return;
	}

	auto self_secret_it = rng_state->secrets.find(self);
	if (self_secret_it == rng_state->secrets.cend()) {
		// hmmmmmmmmmm this bad
		std::cerr << "hmmmmmmmmmm this bad\n";
		return;
	}

	// fire update event
	dispatch(
		P2PRNG_Event::secret,
		P2PRNG::Events::Secret{
			id,
			static_cast<uint16_t>(rng_state->secrets.size()),
			static_cast<uint16_t>(rng_state->contacts.size()),
		}
	);

	// TODO: queue these instead
	for (const auto peer : rng_state->contacts) {
		// TODO: record send success
		send_secret(peer, id, ByteSpan{self_secret_it->second});
	}
}

void ToxP2PRNG::checkHaveAllSecrets(RngState* rng_state, const ByteSpan id) {
	if (rng_state == nullptr) {
		return;
	}

	if (rng_state->secrets.size() != rng_state->contacts.size()) {
		// dont have all secrets yet
		return;
	}
	// have also all secrets o.O

	rng_state->genFinalResult();

	if (rng_state->final_result.empty()) {
		std::cerr << "oh no, oh god\n";
		return;
	}

	// fire done event
	dispatch(
		P2PRNG_Event::done,
		P2PRNG::Events::Done{
			id,
			ByteSpan{rng_state->final_result},
		}
	);
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

P2PRNG::State ToxP2PRNG::getSate(const ByteSpan id_bytes) {
	if (id_bytes.size != ID{}.size()) {
		return P2PRNG::State::UNKNOWN;
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
		return P2PRNG::State::UNKNOWN;
	} else {
		return find_it->second.getState();
	}
}

ByteSpan ToxP2PRNG::getResult(const ByteSpan id_bytes) {
	if (id_bytes.size != ID{}.size()) {
		return {};
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
		return {};
	} else {
		return ByteSpan{find_it->second.final_result};
	}
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

#define _DATA_HAVE(x, error) if ((data.size - curser) < (x)) { error; }

bool ToxP2PRNG::handle_init_with_hmac(Contact3Handle c, const ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet INIT_WITH_HMAC\n";

	if (data.size  < sizeof(uint16_t) + ToxKey{}.size() + 1) {
		// bare minimum size is a single peer with 1byte IS
		std::cerr << "TP2PRNG error: INIT_WITH_HMAC too small\n";
		return false;
	}

	size_t curser = 0;

	//   - peerlist (includes sender, determines fusion order)
	// first numer of peers
	uint16_t peer_count = 0u;
	_DATA_HAVE(sizeof(peer_count), std::cerr << "TP2PRNG error: packet too small, missing peer_count\n"; return false)
	for (size_t i = 0; i < sizeof(peer_count); i++, curser++) {
		peer_count |= uint32_t(data[curser]) << (i*8);
	}

	// then the peers
	_DATA_HAVE(peer_count * ToxKey{}.size(), std::cerr << "TP2PRNG error: packet too small, missing peers\n"; return false)
	std::vector<ToxKey> peers;
	for (size_t peer_i = 0; peer_i < peer_count; peer_i++) {
		auto& new_peer = peers.emplace_back();
		for (size_t i = 0; i < new_peer.size(); i++, curser++) {
			new_peer.data[i] = data[curser];
		}
	}

	if (data.size - curser <= 0) {
		std::cerr << "TP2PRNG error: packet too small, missing inital_state\n";
		return false;
	}

	const ByteSpan inital_state {data.ptr + curser, data.size - curser};

	// lets check if id already exists (after parse, so they cant cheap out)
	if (const auto* rng_state = getRngSate(c, id); rng_state != nullptr) {
		// we already know this maybe we did not send hmac or it got lost

		auto self = rng_state->getSelf();
		if (!static_cast<bool>(self)) {
			std::cerr << "uh wtf\n";
			return true;
		}

		auto hmac_it = rng_state->hmacs.find(self);
		if (hmac_it == rng_state->hmacs.cend()) {
			std::cerr << "uh wtf, bad bad\n";
			return true;
		}

		send_hmac(c, id, ByteSpan{hmac_it->second});

		return true; // mark handled
	}

	// else, its new
	// first resolve peer keys to contacts
	std::vector<Contact3Handle> peer_contacts;
	if (c.all_of<Contact::Components::ToxFriendEphemeral>()) {
		// assuming a 1to1 can only have 2 peers
		assert(peers.size() == 2);
		for (const auto& peer_key : peers) {
			// TODO: accel lookup
			for (const auto& [find_c, tfp] : c.registry()->view<Contact::Components::ToxFriendPersistent>().each()) {
				if (tfp.key == peer_key) {
					peer_contacts.push_back(Contact3Handle{*c.registry(), find_c});
					break;
				}
			}
		}
		if (peer_contacts.size() != peers.size()) {
			std::cerr << "TP2PRNG error: not all peers in peer list could be resolved to contacts\n";
			return true;
		}
	} else if (c.all_of<Contact::Components::ToxGroupPeerEphemeral>()) {
		for (const auto& peer_key : peers) {
			// TODO: accel lookup
			for (const auto& [find_c, tgpp] : c.registry()->view<Contact::Components::ToxGroupPeerPersistent>().each()) {
				if (tgpp.peer_key == peer_key) {
					peer_contacts.push_back(Contact3Handle{*c.registry(), find_c});
					break;
				}
			}
		}
		if (peer_contacts.size() != peers.size()) {
			std::cerr << "TP2PRNG error: not all peers in peer list could be resolved to contacts\n";
			return true;
		}
	} else {
		// yooo how did we get here
		assert(false);
		return true;
	}

	ID new_gen_id;
	for (size_t i = 0; i < new_gen_id.size(); i++) {
		new_gen_id[i] = id[i];
	}

	RngState& new_rng_state = _global_map[new_gen_id];
	new_rng_state.inital_state = std::vector<uint8_t>(inital_state.cbegin(), inital_state.cend());
	new_rng_state.contacts = std::move(peer_contacts);
	new_rng_state.fillInitalStatePreamble(id); // could be faster if we used peer_keys directly

	auto self = new_rng_state.getSelf();
	if (!static_cast<bool>(self)) {
		std::cerr << "TP2PRNG error: failed to find self in new gen\n";
		_global_map.erase(new_gen_id);
		return true;
	}

	std::vector<uint8_t> gen_inital_state = new_rng_state.inital_state_preamble;
	gen_inital_state.insert(gen_inital_state.cend(), inital_state.cbegin(), inital_state.cend());

	std::array<uint8_t, P2PRNG_MAC_LEN> hmac;
	std::array<uint8_t, P2PRNG_LEN + P2PRNG_MAC_KEY_LEN> secret;
	if (p2prng_gen_and_auth(secret.data(), secret.data()+P2PRNG_LEN, hmac.data(), gen_inital_state.data(), gen_inital_state.size()) != 0) {
		std::cerr << "TP2PRNG error: failed to generate and hmac from is\n";
		_global_map.erase(new_gen_id);
		return true;
	}

	new_rng_state.hmacs[self] = hmac;
	new_rng_state.secrets[self] = secret;

	// fire init event?
	dispatch(
		P2PRNG_Event::init,
		P2PRNG::Events::Init{
			id,
			false,
			inital_state,
		}
	);

	// TODO: queue
	// TODO: record result
	send_hmac(c, id, ByteSpan{hmac});

	// fire hmac event
	dispatch(
		P2PRNG_Event::hmac,
		P2PRNG::Events::HMAC{
			id,
			static_cast<uint16_t>(new_rng_state.hmacs.size()),
			static_cast<uint16_t>(new_rng_state.contacts.size()),
		}
	);

	// fun, this is the case in a 1to1
	checkHaveAllHMACs(&new_rng_state, id);

	// not possible, we hare handling INIT_WITH_HMAC here, not with secret
	//checkHaveAllSecrets(&new_rng_state, id);

	return true;
}

bool ToxP2PRNG::handle_hmac(Contact3Handle c, const ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet HMAC\n";

	if (data.size < P2PRNG_MAC_LEN) {
		std::cerr << "TP2PRNG error: HMAC missing from HMAC\n";
		return false;
	}

	ByteSpan hmac {data.ptr, P2PRNG_MAC_LEN};

	if (data.size > hmac.size) {
		std::cerr << "TP2PRNG warning: HMAC pkg has extra data!\n";
	}

	auto* rng_state = getRngSate(c, id);
	if (rng_state == nullptr) {
		return false;
	}

	// check if preexisting (do nothing)
	auto hmac_it = rng_state->hmacs.find(c);
	if (hmac_it == rng_state->hmacs.cend()) {
		// preexisting
		return false;
	}

	// add and do events
	auto& hmac_record = rng_state->hmacs[c];
	for (size_t i = 0; i < P2PRNG_MAC_LEN; i++) {
		hmac_record[i] = hmac[i];
	}

	// fire update event
	dispatch(
		P2PRNG_Event::hmac,
		P2PRNG::Events::HMAC{
			id,
			static_cast<uint16_t>(rng_state->hmacs.size()),
			static_cast<uint16_t>(rng_state->contacts.size()),
		}
	);

	// might be the final one we need
	checkHaveAllHMACs(rng_state, id);

	// :) now the funky part
	// what if we also already have all secrets (a single hmac was the hold up)
	checkHaveAllSecrets(rng_state, id);

	return true;
}

bool ToxP2PRNG::handle_hmac_request(Contact3Handle c, const ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet HMAC_REQUEST\n";

	if (!data.empty()) {
		std::cerr << "TP2PRNG warning: HMAC_REQUEST pkg has extra data!\n";
	}

	const auto* rng_state = getRngSate(c, id);
	if (rng_state == nullptr) {
		return false;
	}

	// no state check necessary

	// find self contact
	Contact3Handle self = rng_state->getSelf();

	if (!static_cast<bool>(self)) {
		std::cerr << "TP2PRNG error: failed to look up self\n";
		return false;
	}

	auto self_hmac_it = rng_state->hmacs.find(self);
	if (self_hmac_it == rng_state->hmacs.cend()) {
		// hmmmmmmmmmm this bad
		std::cerr << "hmmmmmmmmmm this bad\n";
		return false;
	}

	// TODO: queue these instead
	// TODO: record send success
	send_hmac(c, id, ByteSpan{self_hmac_it->second});
	return false;
}

bool ToxP2PRNG::handle_secret(Contact3Handle c, const ByteSpan id, ByteSpan data) {
	std::cerr << "TP2PRNG: got packet SECRET\n";

	if (data.size < P2PRNG_LEN + P2PRNG_MAC_KEY_LEN) {
		std::cerr << "TP2PRNG error: SECRET missing from SECRET\n";
		return false;
	}

	if (data.size > P2PRNG_LEN + P2PRNG_MAC_KEY_LEN) {
		std::cerr << "TP2PRNG warning: SECRET pkg has extra data!\n";
	}

	auto* rng_state = getRngSate(c, id);
	if (rng_state == nullptr) {
		return false;
	}

	// check if preexisting (do nothing)
	auto secret_it = rng_state->secrets.find(c);
	if (secret_it == rng_state->secrets.cend()) {
		// preexisting
		return true; // mark handled
	}

	const auto current_phase = rng_state->getState();

	if (current_phase == P2PRNG::State::SECRET) { // validate if state correct
		const ByteSpan msg {data.ptr, P2PRNG_LEN};
		const ByteSpan key {data.ptr+P2PRNG_LEN, P2PRNG_MAC_KEY_LEN};

		// hmac is only guarrantied to exist if state is correct
		const auto& pre_hmac = rng_state->hmacs.at(c);
		if (p2prng_auth_verify(key.ptr, pre_hmac.data(), msg.ptr, msg.size) != 0) {
			// bad secret
			std::cerr
				<< "########################################\n"
				<< "TP2PRNG error: bad secret, validation failed!\n"
				<< "########################################\n"
			;

			dispatch(
				P2PRNG_Event::val_error,
				P2PRNG::Events::ValError{
					id,
					c,
				}
			);
		}
	}

	// add
	auto& secret_record = rng_state->secrets[c];
	for (size_t i = 0; i < P2PRNG_LEN + P2PRNG_MAC_KEY_LEN; i++) {
		secret_record[i] = data[i];
	}

	if (current_phase != P2PRNG::State::SECRET) {
		// arrived early
		return true;
	}

	// event if phase correct

	dispatch(
		P2PRNG_Event::secret,
		P2PRNG::Events::Secret{
			id,
			static_cast<uint16_t>(rng_state->secrets.size()),
			static_cast<uint16_t>(rng_state->contacts.size()),
		}
	);

	// might have been last, we might be done
	checkHaveAllSecrets(rng_state, id);

	return true;
}

bool ToxP2PRNG::handle_secret_request(Contact3Handle c, const ByteSpan id, ByteSpan data) {
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
	Contact3Handle self = rng_state->getSelf();

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
	// TODO: record send success
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

bool ToxP2PRNG::send_init_with_hmac(
	Contact3Handle c,
	const ByteSpan id,
	const std::vector<Contact3Handle>& peers,
	const ByteSpan inital_state,
	const ByteSpan hmac
) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::INIT_WITH_HMAC, id);
	if (pkg.empty()) {
		return false;
	}

	//   - peerlist (includes sender, determines fusion order)
	// first numer of peers
	const uint16_t peer_count = peers.size();
	for (size_t i = 0; i < sizeof(peer_count); i++) {
		pkg.push_back((peer_count>>(i*8)) & 0xff);
	}

	// second the peers
	for (const auto peer : peers) {
		if (const auto* tfp = peer.try_get<Contact::Components::ToxFriendPersistent>(); tfp != nullptr) {
			pkg.insert(pkg.cend(), tfp->key.data.cbegin(), tfp->key.data.cend());
			continue;
		}

		if (const auto* tgpp = peer.try_get<Contact::Components::ToxGroupPeerPersistent>(); tgpp != nullptr) {
			pkg.insert(pkg.cend(), tgpp->peer_key.data.cbegin(), tgpp->peer_key.data.cend());
			continue;
		}

		if (!peer.any_of<Contact::Components::ToxFriendPersistent, Contact::Components::ToxGroupPeerPersistent>()) {
			return false;
		}
	}


	//   - sender hmac
	pkg.insert(pkg.cend(), hmac.cbegin(), hmac.cend());

	//   - is
	pkg.insert(pkg.cend(), inital_state.cbegin(), inital_state.cend());

	std::cout << "TP2PRNG: seding INIT_WITH_HMAC s:" << pkg.size() << "\n";

	return sendToxPrivatePacket(_t, tfe, tgpe, pkg);
}

bool ToxP2PRNG::send_hmac(Contact3Handle c, ByteSpan id, const ByteSpan hmac) {
	auto [pkg, tfe, tgpe] = prepSendPkgWithID(c, PKG::HMAC, id);
	if (pkg.empty()) {
		return false;
	}

	//   - hmac
	pkg.insert(pkg.cend(), hmac.cbegin(), hmac.cend());

	return sendToxPrivatePacket(_t, tfe, tgpe, pkg);
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

