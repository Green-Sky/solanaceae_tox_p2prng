#include <solanaceae/plugin/solana_plugin_v1.h>

#include <solanaceae/tox_p2prng/tox_p2prng.hpp>
#include <solanaceae/toxcore/tox_interface.hpp>

#include <memory>
#include <limits>
#include <iostream>

static std::unique_ptr<ToxP2PRNG> g_tox_p2prng = nullptr;

constexpr const char* plugin_name = "ToxP2PRNG";

extern "C" {

SOLANA_PLUGIN_EXPORT const char* solana_plugin_get_name(void) {
	return plugin_name;
}

SOLANA_PLUGIN_EXPORT uint32_t solana_plugin_get_version(void) {
	return SOLANA_PLUGIN_VERSION;
}

SOLANA_PLUGIN_EXPORT uint32_t solana_plugin_start(struct SolanaAPI* solana_api) {
	std::cout << "PLUGIN " << plugin_name << " START()\n";

	if (solana_api == nullptr) {
		return 1;
	}

	try {
		auto* tox_i = PLUG_RESOLVE_INSTANCE(ToxI);
		auto* tep_i = PLUG_RESOLVE_INSTANCE(ToxEventProviderI);
		auto* tcm = PLUG_RESOLVE_INSTANCE(ToxContactModel2);

		// static store, could be anywhere tho
		// construct with fetched dependencies
		g_tox_p2prng = std::make_unique<ToxP2PRNG>(*tox_i, *tep_i, *tcm);

		// register types
		PLUG_PROVIDE_INSTANCE(ToxP2PRNG, plugin_name, g_tox_p2prng.get());
		PLUG_PROVIDE_INSTANCE(P2PRNGI, plugin_name, g_tox_p2prng.get());
	} catch (const ResolveException& e) {
		std::cerr << "PLUGIN " << plugin_name << " " << e.what << "\n";
		return 2;
	}

	return 0;
}

SOLANA_PLUGIN_EXPORT void solana_plugin_stop(void) {
	std::cout << "PLUGIN " << plugin_name << " STOP()\n";

	g_tox_p2prng.reset();
}

SOLANA_PLUGIN_EXPORT float solana_plugin_tick(float) {
	return std::numeric_limits<float>::max();
}

} // extern C

