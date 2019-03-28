#include <oath++.hpp>

int main()
{
	// Check version
	if (!Oath::checkVersion(Oath::version()))
	{
		throw std::logic_error("failed version check");
	}

	if (Oath::version().empty())
	{
		throw std::logic_error("no version");
	}

	if (Oath::checkVersion("999.999"))
	{
		throw std::logic_error("passed version check for 999.999");
	}

	// Test initialization
	{
		Oath oath;
	}
	return 0;
}
