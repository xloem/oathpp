#include <oath++.hpp>

const struct {
	time_t now;
	unsigned window;
	std::string otp;
	int expected_rc;
	int otp_pos;
	uint64_t otp_counter;
} tv[] = {
	/* Derived from RFC 6238. */
	{ 0, 10, "94287082", 1, 1, 1},
	{ 1111111100, 10, "07081804", 0, 0, 37037036},
	{ 1111111109, 10, "07081804", 0, 0, 37037036},
	{ 1111111000, 10, "07081804", 3, 3, 37037036},
	{ 1111112000, 99, "07081804", 30, -30, 37037036},
	{ 1111111100, 10, "14050471", 1, 1, 37037037},
	{ 1111111109, 10, "14050471", 1, 1, 37037037},
	{ 1111111000, 10, "14050471", 4, 4, 37037037},
	{ 1111112000, 99, "14050471", 29, -29, 37037037},
};

int main()
{
	Oath::bindata secret = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	                        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30};

	Oath oath;

	for (size_t i = 0; i < sizeof (tv) / sizeof (tv[0]); ++ i)
	{
		int result = oath.totpValidate(secret, tv[i].window, tv[i].otp, tv[i].now);
		if (result != tv[i].otp_pos)
		{
			throw std::logic_error("totp validate failed");
		}

		result = oath.totpValidate(secret, tv[i].window, [=](std::string cmp)
		                           {
		                           	return cmp == tv[i].otp;
		                           }, 8, tv[i].now);
		if (result != tv[i].otp_pos)
		{
			throw std::logic_error("totp validate failed");
		}
	}

	return 0;
}
