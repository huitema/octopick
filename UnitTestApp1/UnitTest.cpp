#include "pch.h"
#include "CppUnitTest.h"
#include "../OctoPairTest/OctoPairTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTestApp1
{
    TEST_CLASS(UnitTest1)
    {
    public:
        TEST_METHOD(LocalAddressTest)
        {
            // TODO: Your test code here
			int ret = LocalAddressDoTest();
			Assert::IsTrue(ret == 0);
        }

        TEST_METHOD(KeyRingTest)
        {
            // TODO: Your test code here
            int ret = KeyRingDoTest();
            Assert::IsTrue(ret == 0);
        }
    };
}