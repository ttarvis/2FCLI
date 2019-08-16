#include <iostream>
#include <chrono>
#include <algorithm>

#include <cryptopp/base32.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include "otp.h"
#include "auth.h"

static const CryptoPP::byte ALPHABET[]          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const std::string base32Decode(std::string& encoded) {
	std::string decoded;

	static int decodingArray[256];
	CryptoPP::Base32Decoder::InitializeDecodingLookupArray(
					decodingArray,
					ALPHABET,
					32,
					true);

	CryptoPP::Base32Decoder decoder;
	CryptoPP::AlgorithmParameters dp = CryptoPP::MakeParameters(
						CryptoPP::Name::DecodingLookupArray(),
						(const int*)decodingArray,
						false);
	decoder.IsolatedInitialize(dp);

	decoder.Attach( new CryptoPP::StringSink(decoded) );
	decoder.Put( (std::uint8_t*)encoded.c_str(), encoded.size());
	decoder.MessageEnd();

	return decoded;
}

std::string getCmdOption(std::vector<std::string> args, const std::string& option) {

	for(auto arg = args.begin(); arg != args.end(); ++arg) {
		if (arg->compare(option) == 0 && ++arg != args.end() ) {
			return std::string(*arg);
		} else if (arg == args.end()) {
			return std::string();
		}
	}
	/*
	auto itr = std::find(args.begin(), args.end(), option);
	if (itr != args.end() && ++itr != args.end()) {
		return itr;
	}
	*/

	return std::string();
}

bool cmdOptionExists(std::vector<std::string> args, const std::string& option) {

	for(auto arg = args.begin(); arg != args.end(); ++arg) {
		if (arg->compare(option) == 0) {
			return true;
		}
	}

	return false;
}

void usage() {
	std::cerr << "How to use this tool" << std::endl;
}

int main(int argc, char* argv[]) {
	const std::string helpFlag = "-h"; // these should be up at the top
	const std::string keyFlag = "-key";
	const std::string hashFlag = "-hash";
	const std::string digitsFlag = "-d";
	std::uint32_t digits = 6;
	std::string encodedKey;

	if (argc < 2) {
		std::cerr << "Incorrect Usage. Operation requires at least 1 argument" << std::endl;
		usage();
		return 1;
	}

	std::vector<std::string> args(argv + 1, argv + argc);

	if (cmdOptionExists(args, helpFlag)) {
		usage();
		return 0;
	}

	if (cmdOptionExists(args, keyFlag)) {
		encodedKey = getCmdOption(args, keyFlag);
		if (encodedKey.empty()) {
			return 1;
		}
	}
	if (encodedKey.empty()) {
		std::cout << "debug, key is empty somehow" << std::endl;
	}
	// at this point there should not be an empty key

	std::string decodedKey;
	decodedKey = base32Decode(encodedKey);

	if (cmdOptionExists(args, digitsFlag)) {
		std::string digitsStr = getCmdOption(args, keyFlag);
		std::int32_t digitsVal = std::stoi(digitsStr);
		if (digitsVal < 6 || digitsVal > 8) {
			digits = std::uint32_t(6);
		}
		digits = std::uint32_t(digitsVal);
	}

	// move the hash and actual call in to here
	if (cmdOptionExists(args, hashFlag)) {
		// todo: should transform to lower case
		std::string hashAlg = getCmdOption(args, hashFlag);
		if (hashAlg == "sha1") {
			AuthOTP<CryptoPP::SHA1> auth (decodedKey, digits);
			auth.printToken();
		} else if (hashAlg == "sha-256") {
			AuthOTP<CryptoPP::SHA256> auth (decodedKey, digits);
			auth.printToken();
		} else {
			// anything else?
			// make a switch statement instead?
		}
	} else {
		AuthOTP<CryptoPP::SHA1> auth (decodedKey, digits);
		auth.printToken();
	}

	return 0;
}
