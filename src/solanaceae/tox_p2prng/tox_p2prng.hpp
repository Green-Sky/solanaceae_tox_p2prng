#pragma once

#include "./p2prng.hpp"

#include <solanaceae/tox_contacts/tox_contact_model2.hpp>

#include <cstdint>

// implements P2PRNGI for tox
// both tox friends(1to1) aswell as tox ngc(NtoN) should be supported
// TODO: use generic packet handling service (eg ngc_ext) instead
class ToxP2PRNG : public P2PRNGI, public ToxEventI {
	ToxI& _t;
	ToxEventProviderI& _tep;
	ToxContactModel2& _tcm;

	enum class PKG : uint8_t {
		INVALID = 0u,

		INIT_WITH_HMAC,
		HMAC,
		HMAC_REQUEST,
		SECRET,
		SECRET_REQUEST,
	};

	public:
		ToxP2PRNG(
			ToxI& t,
			ToxEventProviderI& tep,
			ToxContactModel2& tcm
		);
		~ToxP2PRNG(void);

	public: // p2prng
		std::vector<uint8_t> newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) override;
		std::vector<uint8_t> newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) override;

		P2PRNG::State getSate(const ByteSpan id) override;
		ByteSpan getResult(const ByteSpan id) override;

	protected:
		bool handlePacket(
			Contact3Handle c,
			PKG pkg_type,
			const uint8_t* data,
			const size_t data_size
		);
		bool handleFriendPacket(
			const uint32_t friend_number,
			const uint8_t* data,
			const size_t data_size
		);

		bool handleGroupPacket(
			const uint32_t group_number,
			const uint32_t peer_number,
			const uint8_t* data,
			const size_t data_size,
			const bool _private
		);

		bool parse_init_with_hmac(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);
		bool parse_hmac(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);
		bool parse_hmac_request(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);
		bool parse_secret(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);
		bool parse_secret_request(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);

	protected:
		bool onToxEvent(const Tox_Event_Friend_Lossless_Packet* e) override;
		bool onToxEvent(const Tox_Event_Group_Custom_Packet* e) override;
		bool onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) override;
};
