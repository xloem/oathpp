#include <oath++.hpp>

#include <oath.h>
#include <time.h>

#include <fstream>
#include <sstream>

#define CREDS "tmp.oath"

int main()
{
	time_t faketime = time(0);
	if (faketime != 1165449600)
	{
		throw std::logic_error("Time not faked to 2006-12-07 for test");
	}

	{
		std::ofstream out(CREDS);
		out << R"(# comment
 # test
HOTP/E		bob	-	00
HOTP/E/8	joe	4711	01
HOTP/E/8	silver	4711	3132333435363738393031323334353637383930313233343536373839303132	1	670691	2005-12-07T17:25:42L
HOTP/E/6	jas	1234	3132333435363738393031323334353637383930
HOTP/E/7	rms	6767	3132333435363738393031323334353637383930	10
HOTP		foo	8989	3132333435363738393031323334353637383930	0	755224	2009-12-07T17:25:42L
HOTP/T30	eve	-	00
HOTP/E		plus	+	00
HOTP/E	twouser	-	11
HOTP/E	twouser	-	22
HOTP/E	threeuser	-	1111
HOTP/E	threeuser	-	2222
HOTP/E	threeuser	-	3333
HOTP/E	fouruser	-	111111
HOTP/E	fouruser	-	222222
HOTP/E	fouruser	-	333333
HOTP/E	fouruser	-	444444
HOTP/E	fiveuser	-	11111111
HOTP/E	fiveuser	-	22222222
HOTP/E	fiveuser	-	33333333
HOTP/E	fiveuser	-	44444444
HOTP/E	fiveuser	-	55555555
HOTP	password	-	0815
HOTP	password	test	1630
HOTP	password	darn	2445
#HOTP   nobody  -       00      1       812658  2013-12-21T19:40:21L
# HOTP  nobody  -       11
HOTP    someone -       22
HOTP    nobody  -       1234
HOTP    nobody  -       33
)";
	}

	Oath oath;
	time_t lastOtp;

	try
	{
		oath.authenticateUsersfile("no-such-file", "joe", "755224", 0, "1234");
		throw std::logic_error("authenticateUsersfile succeeded on missing file");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_NO_SUCH_FILE)
			throw;
	}

	try
	{
		oath.authenticateUsersfile(CREDS, "joe", "755224", 0, "1234");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	try
	{
		oath.authenticateUsersfile(CREDS, "bob", "755224", 0, "1234");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	lastOtp = oath.authenticateUsersfile(CREDS, "silver", "599872", 0, "4711");
	if (lastOtp != 1133976342)
	{
		throw std::logic_error("authenticateUsersfile incorrect timestamp");
	}
	oath.authenticateUsersfile(CREDS, "silver", "072768", 1, "4711");
	oath.authenticateUsersfile(CREDS, "silver", "797306", 1, "4711");

	try
	{
		oath.authenticateUsersfile(CREDS, "foo", "755224", 0, "8989");
		throw std::logic_error("authenticateUsersfile succeeded on replayed otp");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_REPLAYED_OTP)
			throw;
	}

	try
	{
		oath.authenticateUsersfile(CREDS, "rms", "755224", 0, "4321");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	oath.authenticateUsersfile(CREDS, "rms", "436521", 10, "6767");

	// Completely invalid OTP

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "386397", 0, "4711");
		throw std::logic_error("authenticateUsersfile succeeded on invalid otp");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	// Next OTP but search window = 0

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "068866", 0);
		throw std::logic_error("authenticateUsersfile succeeded on short window");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_OTP)
			throw;
	}

	// Next OTP but search window = 1

	oath.authenticateUsersfile(CREDS, "eve", "068866", 1);

	// Replay last OTP

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "068866", 1);
		throw std::logic_error("authenticateUsersfile succeeded on replay");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_REPLAYED_OTP)
			throw;
	}

	// Replay previous OTP

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "963013", 1);
		throw std::logic_error("authenticateUsersfile succeeded on replay");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_REPLAYED_OTP)
			throw;
	}

	// OTP in future outside search window

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "892423", 1);
		throw std::logic_error("authenticateUsersfile succeeded on short window");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_OTP)
			throw;
	}

	// OTP in future with good search window

	oath.authenticateUsersfile(CREDS, "eve", "892423", 10);

	// Old OTP within window

	try
	{
		oath.authenticateUsersfile(CREDS, "eve", "630208", 10);
		throw std::logic_error("authenticateUsersfile succeeded on replay");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_REPLAYED_OTP)
			throw;
	}

	// Matches user's second line
	oath.authenticateUsersfile(CREDS, "twouser", "874680", 10);

	// Matches user's third and final line
	oath.authenticateUsersfile(CREDS, "threeuser", "255509", 10);

	// Matches user's third and next-to-last line
	oath.authenticateUsersfile(CREDS, "fouruser", "663447", 10);

	// Incorrect OTP for user with five lines
	try
	{
		oath.authenticateUsersfile(CREDS, "fiveuser", "812658", 10);
		throw std::logic_error("authenticateUsersfile succeeded on incorrect otp");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_OTP)
			throw;
	}

	// Matches user's second line
	oath.authenticateUsersfile(CREDS, "fiveuser", "123001", 10);

	// Matches user's fourth line
	oath.authenticateUsersfile(CREDS, "fiveuser", "893841", 10);

	// Another matches user's second line
	oath.authenticateUsersfile(CREDS, "fiveuser", "746888", 10);

	// Another matches user's fifth line
	oath.authenticateUsersfile(CREDS, "fiveuser", "730790", 10);

	// Too old for user's second line
	try
	{
		oath.authenticateUsersfile(CREDS, "fiveuser", "692901", 10);
		throw std::logic_error("authenticateUsersfile succeeded on incorrect otp");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_OTP)
			throw;
	}

	// password field of +
	oath.authenticateUsersfile(CREDS, "plus", "328482", 1, "4711");
	oath.authenticateUsersfile(CREDS, "plus", "812658", 1, "4712");

	// different tokens with different passwords for one user
	oath.authenticateUsersfile(CREDS, "password", "898463", 5);
	oath.authenticateUsersfile(CREDS, "password", "989803", 5, "test");
	oath.authenticateUsersfile(CREDS, "password", "427517", 5, "darn");

	// valid for first token but incorrect password
	try
	{
		oath.authenticateUsersfile(CREDS, "password", "917625", 5, "nope");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	// valid for second token but incorrect password
	try
	{
		oath.authenticateUsersfile(CREDS, "password", "459145", 5, "nope");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	// valid for first token but password for second user
	try
	{
		oath.authenticateUsersfile(CREDS, "password", "917625", 5, "test");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	// valid for second token but password for first user
	try
	{
		oath.authenticateUsersfile(CREDS, "password", "459145", 5);
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	// valid for third token but password for second user
	try
	{
		oath.authenticateUsersfile(CREDS, "password", "633070", 9, "test");
		throw std::logic_error("authenticateUsersfile succeeded on bad password");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_BAD_PASSWORD)
			throw;
	}

	{
		std::ifstream in(CREDS);
		std::stringstream content;
		content << in.rdbuf();
		std::string compare = R"(# comment
 # test
HOTP/E		bob	-	00
HOTP/E/8	joe	4711	01
HOTP/E/8	silver	4711	3132333435363738393031323334353637383930313233343536373839303132	3	797306	2006-12-07T00:00:00L
HOTP/E/6	jas	1234	3132333435363738393031323334353637383930
HOTP/E/7	rms	6767	3132333435363738393031323334353637383930	15	436521	2006-12-07T00:00:00L
HOTP		foo	8989	3132333435363738393031323334353637383930	0	755224	2009-12-07T17:25:42L
HOTP/T30	eve	-	00	10	892423	2006-12-07T00:00:00L
HOTP/E	plus	+	00	1	812658	2006-12-07T00:00:00L
HOTP/E	twouser	-	11
HOTP/E	twouser	-	22	7	874680	2006-12-07T00:00:00L
HOTP/E	threeuser	-	1111
HOTP/E	threeuser	-	2222
HOTP/E	threeuser	-	3333	3	255509	2006-12-07T00:00:00L
HOTP/E	fouruser	-	111111
HOTP/E	fouruser	-	222222
HOTP/E	fouruser	-	333333	2	663447	2006-12-07T00:00:00L
HOTP/E	fouruser	-	444444
HOTP/E	fiveuser	-	11111111
HOTP/E	fiveuser	-	22222222	5	746888	2006-12-07T00:00:00L
HOTP/E	fiveuser	-	33333333
HOTP/E	fiveuser	-	44444444	9	893841	2006-12-07T00:00:00L
HOTP/E	fiveuser	-	55555555	7	730790	2006-12-07T00:00:00L
HOTP	password	-	0815	2	898463	2006-12-07T00:00:00L
HOTP	password	test	1630	3	989803	2006-12-07T00:00:00L
HOTP	password	darn	2445	4	427517	2006-12-07T00:00:00L
#HOTP   nobody  -       00      1       812658  2013-12-21T19:40:21L
# HOTP  nobody  -       11
HOTP    someone -       22
HOTP    nobody  -       1234
HOTP    nobody  -       33
)";
		if (content.str() != compare)
		{
			throw std::logic_error("usersfile changed in unexpected way");
		}
	}

	return 0;
}
