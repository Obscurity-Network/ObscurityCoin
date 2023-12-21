// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2023 The ObscurityCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <index/txindex.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/context.h>
#include <outputtype.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/descriptor.h>
#include <util/check.h>
#include <util/message.h> // For MessageSign(), MessageVerify()
#include <util/ref.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <stdint.h>
#include <tuple>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

static RPCHelpMan validateaddress()
{
    return RPCHelpMan{"validateaddress",
                "\nReturn information about the given obscuritycoin address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The obscuritycoin address to validate"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "isvalid", "If the address is valid or not. If not, this is the only property returned."},
                        {RPCResult::Type::STR, "address", "The obscuritycoin address validated"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded scriptPubKey generated by the address"},
                        {RPCResult::Type::BOOL, "isscript", "If the key is a script"},
                        {RPCResult::Type::BOOL, "iswitness", "If the address is a witness address"},
                        {RPCResult::Type::NUM, "witness_version", /* optional */ true, "The version number of the witness program"},
                        {RPCResult::Type::STR_HEX, "witness_program", /* optional */ true, "The hex value of the witness program"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("validateaddress", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
                    HelpExampleRpc("validateaddress", "\"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey));

        UniValue detail = DescribeAddress(dest);
        ret.pushKVs(detail);
    }
    return ret;
},
    };
}

static RPCHelpMan createmultisig()
{
    return RPCHelpMan{"createmultisig",
                "\nCreates a multi-signature address with n signature of m keys required.\n"
                "It returns a json object with the address and redeemScript.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The hex-encoded public keys.",
                        {
                            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded public key"},
                        }},
                    {"address_type", RPCArg::Type::STR, /* default */ "legacy", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The value of the new multisig address."},
                        {RPCResult::Type::STR_HEX, "redeemScript", "The string value of the hex-encoded redemption script."},
                        {RPCResult::Type::STR, "descriptor", "The descriptor for this multisig"},
                    }
                },
                RPCExamples{
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\n.", keys[i].get_str()));
        }
    }

    // Get the output type
    OutputType output_type = OutputType::LEGACY;
    if (!request.params[2].isNull()) {
        if (!ParseOutputType(request.params[2].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[2].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    FillableSigningProvider keystore;
    CScript inner;
    const CTxDestination dest = AddAndGetMultisigDestination(required, pubkeys, output_type, keystore, inner);

    // Make the descriptor
    std::unique_ptr<Descriptor> descriptor = InferDescriptor(GetScriptForDestination(dest), keystore);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner));
    result.pushKV("descriptor", descriptor->ToString());

    return result;
},
    };
}

static RPCHelpMan getdescriptorinfo()
{
    return RPCHelpMan{"getdescriptorinfo",
            {"\nAnalyses a descriptor.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "descriptor", "The descriptor in canonical form, without private keys"},
                    {RPCResult::Type::STR, "checksum", "The checksum for the input descriptor"},
                    {RPCResult::Type::BOOL, "isrange", "Whether the descriptor is ranged"},
                    {RPCResult::Type::BOOL, "issolvable", "Whether the descriptor is solvable"},
                    {RPCResult::Type::BOOL, "hasprivatekeys", "Whether the input descriptor contained at least one private key"},
                }
            },
            RPCExamples{
                "Analyse a descriptor\n" +
                HelpExampleCli("getdescriptorinfo", "\"wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR});

    FlatSigningProvider provider;
    std::string error;
    auto desc = Parse(request.params[0].get_str(), provider, error);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("descriptor", desc->ToString());
    result.pushKV("checksum", GetDescriptorChecksum(request.params[0].get_str()));
    result.pushKV("isrange", desc->IsRange());
    result.pushKV("issolvable", desc->IsSolvable());
    result.pushKV("hasprivatekeys", provider.keys.size() > 0);
    return result;
},
    };
}

static RPCHelpMan deriveaddresses()
{
    return RPCHelpMan{"deriveaddresses",
            {"\nDerives one or more addresses corresponding to an output descriptor.\n"
            "Examples of output descriptors are:\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    wpkh(<pubkey>)                       Native segwit P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
            "or more path elements separated by \"/\", where \"h\" represents a hardened child key.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
                {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED_NAMED_ARG, "If a ranged descriptor is used, this specifies the end or the range (in [begin,end] notation) to derive."},
            },
            RPCResult{
                RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::STR, "address", "the derived addresses"},
                }
            },
            RPCExamples{
                "First three native segwit receive addresses\n" +
                HelpExampleCli("deriveaddresses", "\"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu\" \"[0,2]\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValueType()}); // Range argument is checked later
    const std::string desc_str = request.params[0].get_str();

    int64_t range_begin = 0;
    int64_t range_end = 0;

    if (request.params.size() >= 2 && !request.params[1].isNull()) {
        std::tie(range_begin, range_end) = ParseDescriptorRange(request.params[1]);
    }

    FlatSigningProvider key_provider;
    std::string error;
    auto desc = Parse(desc_str, key_provider, error, /* require_checksum = */ true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    if (!desc->IsRange() && request.params.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
    }

    if (desc->IsRange() && request.params.size() == 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range must be specified for a ranged descriptor");
    }

    UniValue addresses(UniValue::VARR);

    for (int i = range_begin; i <= range_end; ++i) {
        FlatSigningProvider provider;
        std::vector<DestinationAddr> scripts;
        if (!desc->Expand(i, key_provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
        }

        for (const DestinationAddr& script : scripts) {
            CTxDestination dest;
            if (!script.ExtractDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Descriptor does not have a corresponding address"));
            }

            addresses.push_back(EncodeDestination(dest));
        }
    }

    // This should not be possible, but an assert seems overkill:
    if (addresses.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unexpected empty result");
    }

    return addresses;
},
    };
}

static RPCHelpMan verifymessage()
{
    return RPCHelpMan{"verifymessage",
                "\nVerify a signed message\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The obscuritycoin address to use for the signature."},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "If the signature is verified or not."
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"LEr4HnaefWYHbMGXcFp2Po1NPRUeIk8km2\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"LEr4HnaefWYHbMGXcFp2Po1NPRUeIk8km2\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"LEr4HnaefWYHbMGXcFp2Po1NPRUeIk8km2\", \"signature\", \"my message\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    switch (MessageVerify(strAddress, strSign, strMessage)) {
    case MessageVerificationResult::ERR_INVALID_ADDRESS:
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");
    case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
    case MessageVerificationResult::ERR_NOT_SIGNED:
        return false;
    case MessageVerificationResult::OK:
        return true;
    }

    return false;
},
    };
}

static RPCHelpMan signmessagewithprivkey()
{
    return RPCHelpMan{"signmessagewithprivkey",
                "\nSign a message with the private key of an address\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to sign the message with."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
                },
                RPCResult{
                    RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
                },
                RPCExamples{
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"LEr4HnaefWYHbMGXcFp2Po1NPRUeIk8km2\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CKey key = DecodeSecret(strPrivkey);
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }

    std::string signature;

    if (!MessageSign(key, strMessage, signature)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
    }

    return signature;
},
    };
}

static RPCHelpMan setmocktime()
{
    return RPCHelpMan{"setmocktime",
        "\nSet the local time to given timestamp (-regtest only)\n",
        {
            {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, UNIX_EPOCH_TIME + "\n"
             "Pass 0 to go back to using the system time."},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().IsMockableChain()) {
        throw std::runtime_error("setmocktime is for regression testing (-regtest mode) only");
    }

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    const int64_t time{request.params[0].get_int64()};
    if (time < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Mocktime can not be negative: %s.", time));
    }
    SetMockTime(time);
    if (request.context.Has<NodeContext>()) {
        for (const auto& chain_client : request.context.Get<NodeContext>().chain_clients) {
            chain_client->setMockTime(time);
        }
    }

    return NullUniValue;
},
    };
}

static RPCHelpMan mockscheduler()
{
    return RPCHelpMan{"mockscheduler",
        "\nBump the scheduler into the future (-regtest only)\n",
        {
            {"delta_time", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of seconds to forward the scheduler into the future." },
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().IsMockableChain()) {
        throw std::runtime_error("mockscheduler is for regression testing (-regtest mode) only");
    }

    // check params are valid values
    RPCTypeCheck(request.params, {UniValue::VNUM});
    int64_t delta_seconds = request.params[0].get_int64();
    if ((delta_seconds <= 0) || (delta_seconds > 3600)) {
        throw std::runtime_error("delta_time must be between 1 and 3600 seconds (1 hr)");
    }

    // protect against null pointer dereference
    CHECK_NONFATAL(request.context.Has<NodeContext>());
    NodeContext& node = request.context.Get<NodeContext>();
    CHECK_NONFATAL(node.scheduler);
    node.scheduler->MockForward(std::chrono::seconds(delta_seconds));

    return NullUniValue;
},
    };
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static RPCHelpMan getmemoryinfo()
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    return RPCHelpMan{"getmemoryinfo",
                "Returns an object containing information about memory usage.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "\"stats\"", "determines what kind of information is returned.\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+)."},
                },
                {
                    RPCResult{"mode \"stats\"",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::OBJ, "locked", "Information about locked memory manager",
                            {
                                {RPCResult::Type::NUM, "used", "Number of bytes used"},
                                {RPCResult::Type::NUM, "free", "Number of bytes available in current arenas"},
                                {RPCResult::Type::NUM, "total", "Total number of bytes managed"},
                                {RPCResult::Type::NUM, "locked", "Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk."},
                                {RPCResult::Type::NUM, "chunks_used", "Number allocated chunks"},
                                {RPCResult::Type::NUM, "chunks_free", "Number unused chunks"},
                            }},
                        }
                    },
                    RPCResult{"mode \"mallocinfo\"",
                        RPCResult::Type::STR, "", "\"<malloc version=\"1\">...\""
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
},
    };
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = LogInstance().EnableCategory(cat);
        } else {
            success = LogInstance().DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

static RPCHelpMan logging()
{
    return RPCHelpMan{"logging",
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + LogInstance().LogCategoriesString() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            ,
                {
                    {"include", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "The categories to add to debug logging",
                        {
                            {"include_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                    {"exclude", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "The categories to remove from debug logging",
                        {
                            {"exclude_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "keys are the logging categories, and values indicates its status",
                    {
                        {RPCResult::Type::BOOL, "category", "if being debug logged or not. false:inactive, true:active"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], [\"libevent\"]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint32_t original_log_categories = LogInstance().GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    uint32_t updated_log_categories = LogInstance().GetCategoryMask();
    uint32_t changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT))) {
            LogInstance().DisableCategory(BCLog::LIBEVENT);
            if (changed_log_categories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    for (const auto& logCatActive : LogInstance().LogCategoriesList()) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
},
    };
}

static RPCHelpMan echo(const std::string& name)
{
    return RPCHelpMan{name,
                "\nSimply echo back the input arguments. This command is for testing.\n"
                "\nIt will return an internal bug report when arg9='trigger_internal_bug' is passed.\n"
                "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in "
                "obscuritycoin-cli and the GUI. There is no server-side difference.",
                {
                    {"arg0", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg1", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg2", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg3", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg4", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg5", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg6", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg7", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg8", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                    {"arg9", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, ""},
                },
                RPCResult{RPCResult::Type::NONE, "", "Returns whatever was passed in"},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (request.fHelp) throw std::runtime_error(self.ToString());

    if (request.params[9].isStr()) {
        CHECK_NONFATAL(request.params[9].get_str() != "trigger_internal_bug");
    }

    return request.params;
},
    };
}

static RPCHelpMan echo() { return echo("echo"); }
static RPCHelpMan echojson() { return echo("echojson"); }

static UniValue SummaryToJSON(const IndexSummary&& summary, std::string index_name)
{
    UniValue ret_summary(UniValue::VOBJ);
    if (!index_name.empty() && index_name != summary.name) return ret_summary;

    UniValue entry(UniValue::VOBJ);
    entry.pushKV("synced", summary.synced);
    entry.pushKV("best_block_height", summary.best_block_height);
    ret_summary.pushKV(summary.name, entry);
    return ret_summary;
}

static RPCHelpMan getindexinfo()
{
    return RPCHelpMan{"getindexinfo",
                "\nReturns the status of one or all available indices currently running in the node.\n",
                {
                    {"index_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "Filter results for an index with a specific name."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {
                            RPCResult::Type::OBJ, "name", "The name of the index",
                            {
                                {RPCResult::Type::BOOL, "synced", "Whether the index is synced or not"},
                                {RPCResult::Type::NUM, "best_block_height", "The block height to which the index is synced"},
                            }
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("getindexinfo", "")
                  + HelpExampleRpc("getindexinfo", "")
                  + HelpExampleCli("getindexinfo", "txindex")
                  + HelpExampleRpc("getindexinfo", "txindex")
                },
                [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const std::string index_name = request.params[0].isNull() ? "" : request.params[0].get_str();

    if (g_txindex) {
        result.pushKVs(SummaryToJSON(g_txindex->GetSummary(), index_name));
    }

    ForEachBlockFilterIndex([&result, &index_name](const BlockFilterIndex& index) {
        result.pushKVs(SummaryToJSON(index.GetSummary(), index_name));
    });

    return result;
},
    };
}

void RegisterMiscRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} },
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys","address_type"} },
    { "util",               "deriveaddresses",        &deriveaddresses,        {"descriptor", "range"} },
    { "util",               "getdescriptorinfo",      &getdescriptorinfo,      {"descriptor"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },
    { "util",               "getindexinfo",           &getindexinfo,           {"index_name"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "mockscheduler",          &mockscheduler,          {"delta_time"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echojson,               {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
