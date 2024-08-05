#pragma once

#include "./p2prng.hpp"

#include <p2prng.h>

#include <solanaceae/tox_contacts/tox_contact_model2.hpp>

#include <entt/container/dense_map.hpp>

#include <cstdint>
#include <vector>

// implements P2PRNGI for tox
// both tox friends(1to1) aswell as tox ngc(NtoN) should be supported
// TODO: use generic packet handling service (eg ngc_ext) instead
class ToxP2PRNG : public P2PRNGI, public ToxEventI {
	ToxI& _t;
	ToxEventProviderI& _tep;
	ToxContactModel2& _tcm;

	public:
		enum class PKG : uint8_t {
			INVALID = 0u,

			INIT_WITH_HMAC,
			HMAC,
			HMAC_REQUEST,
			SECRET,
			SECRET_REQUEST,
		};

		using ID = std::array<uint8_t, 32>;
		struct IDHash {size_t operator()(const ID& a) const {return (a[0] | a[1] << 1*8 | a[2] << 1*16 | a[3] << 1*24) ^ (a[31] | a[30] << 1*8);}};

	private:
		struct RngState {
			// all contacts participating, including self
			std::vector<Contact3Handle> contacts;

			// app given
			std::vector<uint8_t> inital_state;

			// the other stuff needed for full IS (preamble+IS)
			//  - ID
			//  - list of public keys of contacts (same order as later used to calc res)
			std::vector<uint8_t> inital_state_preamble;
			void fillInitalStatePreamble(const ByteSpan id);

			// use contacts instead?
			entt::dense_map<Contact3, std::array<uint8_t, P2PRNG_MAC_LEN>> hmacs;
			entt::dense_map<Contact3, std::array<uint8_t, P2PRNG_LEN + P2PRNG_MAC_KEY_LEN>> secrets;
			entt::dense_map<Contact3, bool> secrets_valid;

			void genFinalResult(void);

			std::vector<uint8_t> final_result; // cached

			P2PRNG::State getState(void) const;
		};
		entt::dense_map<ID, RngState, IDHash> _global_map;

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
			ByteSpan data
		);
		bool handleFriendPacket(
			const uint32_t friend_number,
			ByteSpan data
		);

		bool handleGroupPacket(
			const uint32_t group_number,
			const uint32_t peer_number,
			ByteSpan data,
			const bool _private
		);

		bool handle_init_with_hmac(Contact3Handle c, ByteSpan id, ByteSpan data);
		bool handle_hmac(Contact3Handle c, ByteSpan id, ByteSpan data);
		bool handle_hmac_request(Contact3Handle c, ByteSpan id, ByteSpan data);
		bool handle_secret(Contact3Handle c, ByteSpan id, ByteSpan data);
		bool handle_secret_request(Contact3Handle c, ByteSpan id, ByteSpan data);

		//bool send_init_with_hmac(Contact3Handle c, ByteSpan id, const uint8_t* data, size_t data_size);
		bool send_hmac(Contact3Handle c, ByteSpan id, const ByteSpan hmac);
		bool send_hmac_request(Contact3Handle c, ByteSpan id);
		bool send_secret(Contact3Handle c, ByteSpan id, const ByteSpan secret);
		bool send_secret_request(Contact3Handle c, ByteSpan id);

		RngState* getRngSate(Contact3Handle c, ByteSpan id);

	protected:
		bool onToxEvent(const Tox_Event_Friend_Lossless_Packet* e) override;
		bool onToxEvent(const Tox_Event_Group_Custom_Packet* e) override;
		bool onToxEvent(const Tox_Event_Group_Custom_Private_Packet* e) override;
};
