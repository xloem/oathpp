#include <oath++.hpp>
#include <oath.h>

int main()
{	
	std::string hexsecret = "ABCDEF3435363738393031323334353637abcdef";
	Oath::bindata binsecret = {0xAB, 0xCD, 0xEF, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0xab, 0xcd, 0xef};
	Oath::bindata secret;

	// Hex decoding
	secret = Oath::hex2bin(hexsecret);
	if (secret.size() != 20)
	{
		throw std::logic_error("hex2bin too small");
	}

	Oath::hex2bin("abcd");
	Oath::hex2bin("ABCD");

	try
	{
		Oath::hex2bin("ABC");
		throw std::logic_error("hex2bin too small failed");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_HEX)
			throw;
	}

	try
	{
		Oath::hex2bin("JUNK");
		throw std::logic_error("hex2bin junk failed");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_HEX)
			throw;
	}

	secret = Oath::hex2bin(hexsecret);
	if (secret != binsecret)
	{
		throw std::logic_error("hex2bin decode mismatch");
	}

	// Hex encoding
	
	Oath::bin2hex({});

	if (Oath::bin2hex({'x'}) != "78")
	{
		throw std::logic_error("bin2hex encode mismatch");
	}
	if (Oath::bin2hex({'x', 'x'}) != "7878")
	{
		throw std::logic_error("bin2hex encode mismatch");
	}

	// Base32 encoding
	
	Oath::base32Encode({});
	if (Oath::base32Encode({'f', 'o', 'o'}) != "MZXW6===")
	{
		throw std::logic_error("base32Encode mismatch");
	}
	if (Oath::base32Encode({'f', 'o', 'o', 'b', 'a', 'r'}) != "MZXW6YTBOI======")
	{
		throw std::logic_error("base32Encode mismatch");
	}

	// Base32 decoding

	Oath::base32Decode({});

	try
	{
		Oath::base32Decode("NIXnix");
		throw std::logic_error("base32Decode junk failed");
	}
	catch (OathError e)
	{
		if (e.code().value() != OATH_INVALID_BASE32)
			throw;
	}

	if (Oath::base32Decode("MZXW6===") != Oath::bindata{'f', 'o', 'o'})
	{
		throw std::logic_error("base32Decode mismatch");
	}
	if (Oath::base32Decode("mzxw6===") != Oath::bindata{'f', 'o', 'o'})
	{
		throw std::logic_error("base32Decode mismatch");
	}
	if (Oath::base32Decode("MZ XW 6===") != Oath::bindata{'f', 'o', 'o'})
	{
		throw std::logic_error("base32Decode mismatch");
	}
	if (Oath::base32Decode("MZ XW 6") != Oath::bindata{'f', 'o', 'o'})
	{
		throw std::logic_error("base32Decode mismatch");
	}
	if (Oath::base32Decode("MZXW6YTBOI======") != Oath::bindata{'f', 'o', 'o', 'b', 'a', 'r'})
	{
		throw std::logic_error("base32Decode mismatch");
	}

	if (Oath::base32Decode("gr6d 5br7 25s6 vnck v4vl hlao re").size() != 16)
	{
		throw std::logic_error("base32Decode mismatch");
	}

	return 0;
}
