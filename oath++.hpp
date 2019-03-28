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

	using bindata = std::vector<uint8_t>;
	enum totpHmac
	{
		SHA1,
		SHA256,
		SHA512
	};

	bindata hex2bin(std::string const & hexstr);
	std::string bin2hex(bindata const & binstr);
	bindata base32Decode(std::string const & base32str);
	std::string base32Encode(bindata const & binstr);

	std::string hotpGenerate(bindata const & secret,
	                         uint64_t movingFactor,
	                         unsigned digits,
	                         bool addChecksum = false,
	                         size_t truncationOffset = SIZE_MAX);
	
	int hotpValidate(bindata const & secret,
	                 uint64_t startMovingFactor,
	                 size_t window,
	                 std::string const & otp);

	int hotpValidate(bindata const & secret,
	                 uint64_t startMovingFactor,
	                 size_t window,
	                 unsigned digits,
	                 std::function<bool(std::string const &)> cmpOtp);

	std::string totpGenerate(bindata const & secret,
	                         unsigned digits,
	                         time_t now = 0,
	                         unsigned timeStepSize = 30,
	                         time_t startOffset = 0,
	                         totpHmac hmac = SHA1);

	int totpValidate(bindata const & secret,
	                 size_t window,
	                 std::string const & otp,
	                 time_t now = 0,
	                 unsigned timeStepSize = 30,
	                 time_t startOffset = 0,
	                 totpHmac hmac = SHA1);

	int totpValidate(bindata const & secret,
	                 size_t window,
	                 std::function<bool(std::string const &)> cmpOtp,
	                 unsigned digits,
	                 time_t now = 0,
	                 unsigned timeStepSize = 30,
	                 time_t startOffset = 0,
	                 totpHmac hmac = SHA1);

	time_t authenticateUsersfile(std::string usersfile,
	                             std::string username,
	                             std::string otp,
	                             size_t window,
	                             std::string passwd = "");

	// example version: "2.4.1"
	static std::string version();
	static bool checkVersion(std::string reqVersion);
};

class OathError : public std::system_error
{
public:
	OathError(int err);
	OathError(int err, std::string what);
};
