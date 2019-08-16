/*
 *
 */

#ifndef __AUTH_H__
#define __AUTH_H__

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include "auth.h"

template <class T>
class AuthOTP {
        std::uint32_t digits;
	std::uint32_t token;
	std::uint64_t timeLeft;
        std::string key; // this is after decoding
	T hashAlg;
        public:
		AuthOTP(std::string s);
		AuthOTP(std::string s, std::uint32_t d);
		AuthOTP(std::string s, T hash);
		AuthOTP(std::string s, std::uint32_t d, T hash);
		void setDigits(std::uint32_t d);
		uint32_t getToken();
		void printToken();
	private:
		void generateToken();
};

template <class T>
AuthOTP<T>::AuthOTP(std::string s) {
        digits = 6;
        key = s;
}

template <class T>
AuthOTP<T>::AuthOTP(std::string s, std::uint32_t d) {
        // may want to check range of d
        digits = d;
        key = s;
}

template <class T>
void AuthOTP<T>::setDigits(std::uint32_t d) {
        digits = d;
}

template <class T>
void AuthOTP<T>::generateToken() {
        std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()
        );
	auto now = std::chrono::system_clock::now();
        std::uint64_t Tx = std::uint64_t(ns.count());
        timeLeft =  30 - ((Tx / 1000000000ull) % 30);
        token = totp(key, Tx, 0, std::uint64_t(30), digits, hashAlg);
}

template <class T>
std::uint32_t AuthOTP<T>::getToken() {
        return token;
}

template <class T>
void AuthOTP<T>::printToken() {
        generateToken();
	std::string tokenStr = std::to_string(token);
	// todo: probably not efficient, so make it efficient
	for(auto l = tokenStr.length(); l < digits; l++) {
		tokenStr.insert(0, "0");
	}

        std::cout << "token: " << tokenStr << "\nseconds remaining: " << timeLeft << std::endl;
}

#endif
