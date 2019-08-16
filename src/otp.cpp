/*
 * Copyright (c) 2019 Terence G. Tarvis
 *
 * TKTK License
 */

#include <iostream>

#include <sys/time.h>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include "otp.h"

void int64ToBytes(std::uint8_t array[], std::uint64_t n) {
	for (int i = 0; i < 8; i++) {
		array[7 - i] = (n >> (i * 8));
	}
	/*
	array[0] = (std::uint8_t)(n >> 56);
	array[1] = (std::uint8_t)(n >> 48);
	array[2] = (std::uint8_t)(n >> 40);
	array[3] = (std::uint8_t)(n >> 32);
	array[4] = (std::uint8_t)(n >> 24);
	array[5] = (std::uint8_t)(n >> 16);
	array[6] = (std::uint8_t)(n >> 8);
	array[7] = (std::uint8_t)(n);
	*/
}

std::int32_t extract31(const std::vector<std::uint8_t> hmac) {
	// takes the last byte and extracts the last 4 bits 0xf represents four bits 1111
	// the rest are 0 so only bits that are set at 1 will be left
	const std::int32_t offset = hmac[hmac.size()-1] & 0xf;

	const std::int32_t bits = ((hmac[offset] & 0x7f) << 24)
			| ((hmac[offset+1] & 0xff) << 16)
			| ((hmac[offset+2] & 0xff) << 8 )
			| ((hmac[offset+3] & 0xff) << 0 );

	return bits; // return only 31 bits
}

std::uint32_t truncate(const std::vector<std::uint8_t> hmac, const std::uint32_t digits) {
	std::int32_t d = extract31(hmac);
	std::int32_t m = 1000000;

	// don't want to import cmath lib
	if(digits==6) m = 1000000;
	if(digits==7) m = 10000000;
	if(digits==8) m = 100000000;

	const std::int32_t tokenVal(d % m);

	return tokenVal;
}

// key is secret
// hmac should be one of the hmac algorithms
/*
template <class T>
std::int32_t hotp(const std::string& key, const std::uint64_t counter, const std::uint32_t digits) {
	CRYPTOPP_ASSERT(key);

	std::uint8_t counterArray[ sizeof(std::uint64_t)];
	int64ToBytes(counterArray, counter);

	CryptoPP::HMAC<T> hmac;
	std::vector<std::uint8_t> buffer(hmac.DigestSize());

	//hmac.SetKey(key.begin(), key.size());
	hmac.SetKey( (const std::uint8_t*)key.c_str(), key.size());
	hmac.CalculateDigest(&buffer[0], counterArray, 8);

	auto token = truncate(buffer, digits);	

	return token;
}

// these generic classes could be made in to <CryptoPP::T> or something I bet
template <class T>
std::int32_t totp(const std::string& key,
			const std::uint64_t timeNow,
			const std::uint64_t epoch,
			const std::uint64_t timeStep,
			const std::uint32_t, digits,
			T hash) {

	std::int64_t timeCounter = timeNow / 30000000000ul; // I don't know why this works
	auto token = hotp(key, timeCounter, digits);

	return token;
}
*/

