#pragma once

#include <solanaceae/contact/contact_model3.hpp>
#include <solanaceae/util/event_provider.hpp>
#include <solanaceae/util/span.hpp>

#include <cstdint>
#include <vector>

// while it is an implementation detail, a general flow could look like this:
//
// Legend: [Events] {Network}
//
// ## Being the Initiator:
//
//                      +------------------------------+
// [INIT]               | Start (with IS and gen+hmac) |
//                      +------------------------------+
//                        |
//                        v
//               #####  +-------------------+
// [HMAC]        #      | Send out own HMAC |             -->{IS+HMAC}
// [Own ]        # H P  +-------------------*
//               # M h    |
//               # A-a    |
// [...   ]      # C s   ~ Waiting for all other HMACs ~  <--{Others HMACs}
// [HMAC  ]      #   e    |
// [Others]      #        v
//               #####  +----------------+
//                      | Have All HMACs |
//                      +----------------+
//                        |
//                        v
//               #####  +---------------------+
// [Secret]      # S    | Send out own Secret |            -->{Secret}
// [Own   ]      # e P  +---------------------+
//               # c h    |
//               # r-a  ~ Waiting for all other Secrets ~  <--{Others Secrets}
// [...   ]      # e s    |
// [Secret]      # t e    v
// [Others]      #      +------------------+
//               #####  | Have All Secrets |
//                      +------------------+
//                        |
//                        v
//                      +--------------+
// [Done]               | Final Result |
//                      +--------------+
//
//
// Contributing looks almost the same, the inital state is different though

namespace P2PRNG {
	enum State : uint8_t {
		UNKNOWN, // invalid

		INIT, // inital params (incoming or outgoing?)
		HMAC, // got a hmac (phase start will be denoted by the initiators hmac)
		SECRET, // got a secret (phase start will be denoted by own, secrets received before we have all hmacs get queued up)

		DONE, // rng is done, event contains full rng
	};
} // P2PRNG

namespace P2PRNG::Events {

	struct Init {
		const ByteSpan id;

		bool self {false}; // who started the rng
		const ByteSpan initial_state;
	};

	// received an hmac (or own, when first)
	struct HMAC {
		const ByteSpan id;

		uint16_t have;
		uint16_t out_of;
	};

	// received a secret (or own, when first)
	struct Secret {
		const ByteSpan id;

		uint16_t have;
		uint16_t out_of;
	};

	struct Done {
		const ByteSpan id;

		const ByteSpan result;
	};

	//NO_HMAC, // fired when a peer does not provide an hmac after a set timeout?

	// fired when a secret does not match the hmac
	struct ValError {
		const ByteSpan id;
		Contact3 c;
		// TODO: more info?
	};

	// TODO: what about other peers never receiving all secrets (or hmacs)

} // P2PRNG::Events

enum class P2PRNG_Event : uint16_t {
	init,
	hmac,
	secret,
	done,

	val_error,

	MAX
};

struct P2PRNGEventI {
	using enumType = P2PRNG_Event;

	virtual ~P2PRNGEventI(void) {}

	virtual bool onEvent(const P2PRNG::Events::Init&) { return false; }
	virtual bool onEvent(const P2PRNG::Events::HMAC&) { return false; }
	virtual bool onEvent(const P2PRNG::Events::Secret&) { return false; }
	virtual bool onEvent(const P2PRNG::Events::Done&) { return false; }
	virtual bool onEvent(const P2PRNG::Events::ValError&) { return false; }
};
using P2PRNGEventProviderI = EventProviderI<P2PRNGEventI>;

// general p2prng interface
struct P2PRNGI : public P2PRNGEventProviderI {
	static constexpr const char* version {"1"};

	// returns unique id, you can then use when listen to events
	// chooses peers depending on C, if C is a group it (tries?) to use everyone?
	virtual std::vector<uint8_t> newGernation(Contact3Handle c, const ByteSpan initial_state_user_data) = 0;
	// manually tell it which peers to use
	virtual std::vector<uint8_t> newGernationPeers(const std::vector<Contact3Handle>& c_vec, const ByteSpan initial_state_user_data) = 0;


	// TODO: do we really need this, or are event enough??
	// state api
	virtual P2PRNG::State getSate(const ByteSpan id) = 0;
	// getHMAC
	// getSecret

	virtual ByteSpan getResult(const ByteSpan id) = 0;
};

