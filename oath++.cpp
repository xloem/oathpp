#include <oath++.hpp>
#include <oath.h>
#include <ctime>

// hmac flags introduced with header version 2.6
#define HAVE_FLAGS (OATH_VERSION_NUMBER > 0x02060000)

#if ! HAVE_FLAGS
	#define oath_totp_generate2(secret, secretlen, now, step, start, digits, flags, out) \
		oath_totp_generate(secret, secretlen, now, step, start, digits, out)
	#define oath_totp_validate4(secret, secretlen, now, step, start, window, out1, out2, flags, otp) \
		oath_totp_validate3(secret, secretlen, now, step, start, window, out1, out2, otp)
	#define oath_totp_validate4_callback(secret, secretlen, now, step, start, digits, window, out1, out2, flags, otpcheck, otp) \
		oath_totp_validate3_callback(secret, secretlen, now, step, start, digits, window, out1, out2, otpcheck, otp)
#endif

class OathErrorCategory : public std::error_category
{
public:
	const char* name() const noexcept override
	{
		return "OATH";
	}
	std::string message(int condition) const override
	{
		return std::string(oath_strerror_name(condition)) + ": " + oath_strerror(condition);
	}
} static oathErrorCategory;

OathError::OathError(int err)
: std::system_error(err, oathErrorCategory)
{ }

OathError::OathError(int err, std::string what)
: std::system_error(err, oathErrorCategory, what)
{ }

static inline int checkErr(int err)
{
	if (err < OATH_OK)
	{
		throw OathError(err);
	}
	return err;
}

Oath::Oath()
{
	checkErr(oath_init());
}

Oath::~Oath()
{
	checkErr(oath_done());
}

Oath::bindata Oath::hex2bin(std::string const & hexstr)
{
	size_t len;
	checkErr(oath_hex2bin(hexstr.c_str(), nullptr, &len));
	bindata ret(len, 0);
	checkErr(oath_hex2bin(hexstr.c_str(), reinterpret_cast<char*>(ret.data()), &len));
	return ret;
}

std::string Oath::bin2hex(Oath::bindata const & binstr)
{
	std::string ret(2*binstr.size(), 0);
	oath_bin2hex(reinterpret_cast<const char*>(binstr.data()), binstr.size(), &ret[0]);
	return ret;
}

Oath::bindata Oath::base32Decode(std::string const & base32str)
{
	size_t len;
	char * out;

	checkErr(oath_base32_decode(base32str.c_str(), base32str.size(), &out, &len));

	bindata ret(out, out + len);

	free(out);

	return ret;
}

std::string Oath::base32Encode(bindata const & binstr)
{
	size_t len;
	char * out;

	checkErr(oath_base32_encode(reinterpret_cast<const char *>(binstr.data()), binstr.size(), &out, &len));

	std::string ret(out, out + len);

	free(out);

	return ret;
}

std::string Oath::hotpGenerate(Oath::bindata const & secret,
                               uint64_t movingFactor,
                               unsigned digits,
                               bool addChecksum,
                               size_t truncationOffset)
{
	std::string output(OATH_HOTP_LENGTH(digits, addChecksum), 0);

	checkErr(oath_hotp_generate(reinterpret_cast<const char *>(secret.data()),
	                            secret.size(),
	                            movingFactor,
	                            digits,
	                            addChecksum,
	                            truncationOffset,
	                            &output[0]));

	return output;
}

int Oath::hotpValidate(Oath::bindata const & secret,
                       uint64_t startMovingFactor,
                       size_t window,
                       std::string const & otp)
{
	return checkErr(oath_hotp_validate(reinterpret_cast<const char *>(secret.data()),
	                                   secret.size(),
	                                   startMovingFactor,
	                                   window,
	                                   otp.data()));
}

static int validate_strcmp_function(void * handle, const char * testOtp)
{
	std::function<bool(std::string const &)> * cmpOtp;
	cmpOtp = static_cast<decltype(cmpOtp)>(handle);
	try
	{
		return (*cmpOtp)(testOtp) ? 0 : 1;
	}
	catch (...)
	{
		return -1;
	}
}

int Oath::hotpValidate(Oath::bindata const & secret,
                       uint64_t startMovingFactor,
                       size_t window,
                       unsigned digits,
                       std::function<bool(std::string const &)> strcmpOtp)
{
	return checkErr(oath_hotp_validate_callback(reinterpret_cast<const char *>(secret.data()),
	                                            secret.size(),
	                                            startMovingFactor,
	                                            window,
	                                            digits,
	                                            validate_strcmp_function,
	                                            &strcmpOtp));
}

static inline int hmac2flags(Oath::totpHmac hmac)
{
	switch (hmac)
	{
	case Oath::SHA1:
		return 0;
	#if HAVE_FLAGS
	case Oath::SHA256:
		return OATH_TOTP_HMAC_SHA256;
	case Oath::SHA512:
		return OATH_TOTP_HMAC_SHA512;
	#endif // HAVE_FLAGS
	default:
		throw OathError(OATH_CRYPTO_ERROR, "unsupported hmac algorithm");
	};
}

std::string Oath::totpGenerate(Oath::bindata const & secret,
                               unsigned digits,
                               time_t now,
                               unsigned timeStepSize,
                               time_t startOffset,
                               totpHmac hmac)
{
	std::string ret(digits, 0);
	int flags = hmac2flags(hmac);
	(void) flags;
	checkErr(oath_totp_generate2(reinterpret_cast<const char *>(secret.data()),
	                             secret.size(),
	                             now ? now : time(nullptr),
	                             timeStepSize,
	                             startOffset,
	                             digits,
	                             flags,
	                             &ret[0]));
	return ret;
}

int Oath::totpValidate(Oath::bindata const & secret,
                       size_t window,
                       std::string const & otp,
                       time_t now,
                       unsigned timeStepSize,
                       time_t startOffset,
	               totpHmac hmac)
{
	int otpPos;
	uint64_t otpCounter;
	int flags = hmac2flags(hmac);
	(void) flags;
	checkErr(oath_totp_validate4(reinterpret_cast<const char *>(secret.data()),
	                             secret.size(),
	                             now ? now : time(nullptr),
	                             timeStepSize,
	                             startOffset,
	                             window,
	                             &otpPos,
	                             &otpCounter,
	                             flags,
	                             otp.data()));
	return otpPos;
}

int Oath::totpValidate(Oath::bindata const & secret,
                       size_t window,
	               std::function<bool(std::string const &)> cmpOtp,
                       unsigned digits,
                       time_t now,
                       unsigned timeStepSize,
                       time_t startOffset,
	               totpHmac hmac)
{
	int otpPos;
	uint64_t otpCounter;
	int flags = hmac2flags(hmac);
	(void) flags;
	checkErr(oath_totp_validate4_callback(reinterpret_cast<const char *>(secret.data()),
	                                      secret.size(),
	                                      now ? now : time(nullptr),
	                                      timeStepSize,
	                                      startOffset,
	                                      digits,
	                                      window,
	                                      &otpPos,
	                                      &otpCounter,
	                                      flags,
	                                      validate_strcmp_function,
	                                      &cmpOtp));
	return otpPos;
}

time_t Oath::authenticateUsersfile(std::string usersfile,
                                   std::string usersname,
                                   std::string otp,
                                   size_t window,
                                   std::string passwd)
{
	time_t lastOtp;
	checkErr(oath_authenticate_usersfile(usersfile.c_str(),
	                                     usersname.c_str(),
	                                     otp.c_str(),
	                                     window,
	                                     passwd.size() ? passwd.c_str() : nullptr,
	                                     &lastOtp));
	return lastOtp;
}

std::string Oath::version()
{
	return OATH_VERSION;
}

bool Oath::checkVersion(std::string reqVersion)
{
	return oath_check_version(reqVersion.c_str()) != nullptr;
}
