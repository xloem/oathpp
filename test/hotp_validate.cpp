#include <oath++.hpp>
#include <oath.h>

#define MAX_DIGIT 8
#define MAX_ITER 20

std::string expect[MAX_DIGIT + 1][MAX_ITER] = {
	/* digit 0 */
	{},
	/* digit 1 */
	{},
	/* digit 2 */
	{},
	/* digit 3 */
	{},
	/* digit 4 */
	{},
	/* digit 5 */
	{},
	/* digit 6 */
	{
	 /* The first ten of these match the values in RFC 4226. */
	 "755224",
	 "287082",
	 "359152",
	 "969429",
	 "338314",
	 "254676",
	 "287922",
	 "162583",
	 "399871",
	 "520489",
	 "403154",
	 "481090",
	 "868912",
	 "736127",
	 "229903",
	 "436521",
	 "186581",
	 "447589",
	 "903435",
	 "578337"},
	/* digit 7 */
	{
	 "4755224",
	 "4287082",
	 "7359152",
	 "6969429",
	 "0338314",
	 "8254676",
	 "8287922",
	 "2162583",
	 "3399871",
	 "5520489",
	 "2403154",
	 "3481090",
	 "7868912",
	 "3736127",
	 "5229903",
	 "3436521",
	 "2186581",
	 "4447589",
	 "1903435",
	 "1578337",
	 },
	/* digit 8 */
	{
	 "84755224",
	 "94287082",
	 "37359152",
	 "26969429",
	 "40338314",
	 "68254676",
	 "18287922",
	 "82162583",
	 "73399871",
	 "45520489",
	 "72403154",
	 "43481090",
	 "47868912",
	 "33736127",
	 "35229903",
	 "23436521",
	 "22186581",
	 "94447589",
	 "71903435",
	 "21578337",
	 }
};

int main()
{
	Oath::bindata secret = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	                        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30};

	Oath oath;

	for (unsigned digits = 6; digits <= MAX_DIGIT; ++ digits)
	{
		for (uint64_t movingFactor = 0; movingFactor < MAX_ITER; ++ movingFactor)
		{
			uint64_t result;

			result = oath.hotpValidate(secret, 0, 20, expect[digits][movingFactor]);
			if (result != movingFactor)
			{
				throw std::logic_error("hotp validate failed");
			}

			for (size_t i = 0; i < movingFactor; ++ i)
			{
				try
				{
					oath.hotpValidate(secret, 0, i, expect[digits][movingFactor]);
					throw std::logic_error("unexpected validate result");
				}
				catch (OathError e)
				{
					if (e.code().value() != OATH_INVALID_OTP)
						throw;
				}
			}

			result = oath.hotpValidate(secret, 0, 20, expect[digits][movingFactor].size(),
			                           [=](std::string cmp)
			                           {
			                           	return expect[digits][movingFactor] == cmp;
			                           });
			if (result != movingFactor)
			{
				throw std::logic_error("hotp validate callback failed");
			}

			for (size_t i = 0; i < movingFactor; ++ i)
			{
				try
				{
					oath.hotpValidate(secret, 0, i, expect[digits][movingFactor].size(),
					                  [=](std::string cmp)
					                  {
					                  	return expect[digits][movingFactor] == cmp;
					                  });
					throw std::logic_error("unexpected validate result");
				}
				catch (OathError e)
				{
					if (e.code().value() != OATH_INVALID_OTP)
						throw;
				}
			}
		}
	}

	return 0;
}
