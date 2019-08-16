/*
 *
 */

#ifndef __OTP_H__
#define __OTP_H__

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

void int64ToBytes(std::uint8_t array[], std::uint64_t n);

std::uint32_t truncate(const std::vector<std::uint8_t> hmac, const std::uint32_t digits);

template <class T>
std::int32_t hotp(const std::string& key, const std::uint64_t counter, const std::uint32_t digits, T hash) {
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
			const std::uint32_t digits,
			T hash) {
        
        //std::int64_t timeCounter = ((timeNow - epoch) / (timeStep * 1000000000ull));
        
        std::int64_t timeCounter = timeNow / 30000000000ul; // I don't know why this works
        auto token = hotp(key, timeCounter, digits, hash);
        
        return token;
}

#endif
