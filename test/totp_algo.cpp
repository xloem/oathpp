#include <oath++.hpp>
#include <oath.h>

const struct {
	time_t secs;
	uint64_t T;
	std::string otp;
	std::string sha256otp;
	std::string sha512otp;
} tv[] = {
	/* From RFC 6238. */
	{ 59, 0x0000000000000001, "94287082", "46119246", "90693936" },
	{ 1111111109, 0x00000000023523EC, "07081804", "68084774", "25091201" },
	{ 1111111111, 0x00000000023523ED, "14050471", "67062674", "99943326" },
	{ 1234567890, 0x000000000273EF07, "89005924", "91819424", "93441116" },
	{ 2000000000, 0x0000000003F940AA, "69279037", "90698825", "38618901" },
	{ 20000000000, 0x0000000027BC86AA, "65353130", "77737706", "47863826" }
};

int main()
{
	Oath::bindata secret20 = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
	Oath::bindata secret32 = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};
	Oath::bindata secret64 = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	                          '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4'};

	Oath oath;

	for (size_t i = 0; i < sizeof (tv) / sizeof (tv[0]); ++ i)
	{
		std::string otp = oath.totpGenerate(secret20, 8, tv[i].secs);
		if (otp != tv[i].otp)
		{
			throw std::logic_error("incorrect totp, 32-bit time_t?");
		}

		if (Oath::checkVersion("2.6.0"))
		{
			otp = oath.totpGenerate(secret32, 8, tv[i].secs, 30, 0, Oath::SHA256);
			if (otp != tv[i].sha256otp)
			{
				throw std::logic_error("incorrect sha256 totp");
			}

			otp = oath.totpGenerate(secret64, 8, tv[i].secs, 30, 0, Oath::SHA512);
			if (otp != tv[i].sha512otp)
			{
				throw std::logic_error("incorrect sha512 totp");
			}
		}
		else
		{
			try
			{
				oath.totpGenerate(secret32, 8, tv[i].secs, 30, 0, Oath::SHA256);
				throw std::logic_error("oath somehow produced sha256 hash with old version");
			}
			catch (OathError e)
			{
				if (e.code().value() != OATH_CRYPTO_ERROR)
					throw;
			}

			try
			{
				oath.totpGenerate(secret64, 8, tv[i].secs, 30, 0, Oath::SHA512);
				throw std::logic_error("oath somehow produced sha512 hash with old version");
			}
			catch (OathError e)
			{
				if (e.code().value() != OATH_CRYPTO_ERROR)
					throw;
			}
		}
	}

	return 0;
}
