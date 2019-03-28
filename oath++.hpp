#pragma once

#include <functional>
#include <string>
#include <system_error>
#include <vector>

class Oath
{
public:
	Oath();
	~Oath();

	// a datatype for secret keys
	using bindata = std::vector<uint8_t>;

	enum totpHmac
	{
		SHA1, // default, prefer 20-byte secrets
		SHA256, // requires liboath >= 2.6, prefer 32-byte secrets
		SHA512  // requires liboath >= 2.6, prefer 64-byte secrets
	};

	// OATH library version, such as "2.4.1"
	static std::string version();

	// compare library version to passed string, true if equal or more recent
	static bool checkVersion(std::string reqVersion);

	// convert hex string to binary data with validation
	static bindata hex2bin(std::string const & hexstr);

	// convert binary data to hex string
	static std::string bin2hex(bindata const & binstr);

	// decode a base32 encoded string into binary data with validation
	static bindata base32Decode(std::string const & base32str);

	// encode binary data into a base32 string
	static std::string base32Encode(bindata const & binstr);

	// generate a one-time-password using the HOTP algorithm as described in RFC 4226
	// 	secret: shared key
	// 	movingFactor: counter indicating which OTP to generate
	// 	digits: number of requested digits excluding checksum
	// 	        currently only values 6, 7, and 8 for digits are supported by liboath
	// 	addChecksum: whether to add a checksum digit, currently ignored by liboath
	// 	truncationOffset: use a specific truncation offset
	// returns: generated OTP
	std::string hotpGenerate(bindata const & secret,
	                         uint64_t movingFactor,
	                         unsigned digits,
	                         bool addChecksum = false,
	                         size_t truncationOffset = SIZE_MAX);

	// validate an OTP according to OATH HOTP algorithm per RFC 4226
	// 	secret: shared key
	// 	startMovingFactor: start counter in OTP stream
	// 	window: how many OTPs after start counter to test
	// 	otp: the OTP to validate
	// returns: match position in OTP window past start counter, or throws OathError if not found
	int hotpValidate(bindata const & secret,
	                 uint64_t startMovingFactor,
	                 size_t window,
	                 std::string const & otp);

	// validate an OTP according to OATH HOTP algorithm per RFC 4226
	// 	secret: shared key
	// 	startMovingFactor: start counter in OTP stream
	// 	window: how many OTPs after start counter to test
	// 	digits: number of requested digits in the OTP
	// 	cmpOtp: function to test OTPs, returning true when the correct one is passed
	// returns: match position in OTP window past start counter, or throws OathError if not found
	int hotpValidate(bindata const & secret,
	                 uint64_t startMovingFactor,
	                 size_t window,
	                 unsigned digits,
	                 std::function<bool(std::string const &)> cmpOtp);

	// generate a one-time-password using the time-variant TOTP algorithm described in RFC 6238
	// 	secret: shared key
	// 	digits: number of requested digits in the OTP, excluding checksum
	// 	        currently only values 6, 7 and 8 for digits are supported by liboath
	// 	now: unix time in seconds to compute TOTP for, defaults to system time
	// 	timeStepSize: seconds between OTP change steps
	// 	startOffset: unix time of first OTP step; using the epoch (0) is conventional
	// 	hmac: MAC function to use, supported only for liboath >= 2.6
	// returns: generated OTP
	std::string totpGenerate(bindata const & secret,
	                         unsigned digits,
	                         time_t now = ~0,
	                         unsigned timeStepSize = 30,
	                         time_t startOffset = 0,
	                         totpHmac hmac = SHA1);

	// validate an OTP according to OATH TOTP algorithm per RFC 6238
	// 	secret: shared key
	// 	window: how many OTPs after/before start OTP to test
	// 	otp: the OTP to validate
	// 	now: unix time in seconds to vlidate TOTP for, defaults to system time
	// 	timeStepSize: seconds between OTP change steps
	//	startOffset: unix time of first OTP step; using the epoch (0) is conventional
	//	hmac: MAC function to use, supported only for liboath >= 2.6
	// returns: match position in OTP window, or throws OathError if not found
	int totpValidate(bindata const & secret,
	                 size_t window,
	                 std::string const & otp,
	                 time_t now = ~0,
	                 unsigned timeStepSize = 30,
	                 time_t startOffset = 0,
	                 totpHmac hmac = SHA1);

	// validate an OTP according to OATH TOTP algorithm per RFC 6238
	// 	secret: shared key
	// 	window: how many OTPs after/before start OTP to test
	// 	digits: number of requested digits in the OTP
	// 	        currently only values of 6, 7, or 8 are supported by liboath
	// 	cmpOtp: function to test OTPs, returning true when the correct one is passed
	// 	now: unix time in seconds to vlidate TOTP for, defaults to system time
	// 	timeStepSize: seconds between OTP change steps
	//	startOffset: unix time of first OTP step; using the epoch (0) is conventional
	//	hmac: MAC function to use, supported only for liboath >= 2.6
	// returns: match position in OTP window, or throws OathError if not found
	int totpValidate(bindata const & secret,
	                 size_t window,
	                 unsigned digits,
	                 std::function<bool(std::string const &)> cmpOtp,
	                 time_t now = ~0,
	                 unsigned timeStepSize = 30,
	                 time_t startOffset = 0,
	                 totpHmac hmac = SHA1);

	// authenticate user with one-time-password.
	// credentials are read and updated from a text file
	// 	usersfile: filename to read and update, UsersFile format
	// 	username: name of user in file
	// 	otp: one-time password for authentication
	// 	window: how many past/future OTPs to search
	// 	passwd: string with password
	// returns: time of last successful authentication, or throws OathError if otp fails
	time_t authenticateUsersfile(std::string usersfile,
	                             std::string username,
	                             std::string otp,
	                             size_t window,
	                             std::string passwd = "");
};

// thrown for all liboath errors
// .what() will return an error-specific descriptive message
// associated error codes are numerically equal to those listed in <oath.h>
class OathError : public std::system_error
{
public:
	OathError(int err);
	OathError(int err, std::string what);
};
