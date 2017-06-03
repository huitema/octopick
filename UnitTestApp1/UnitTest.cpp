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
			int ret = LocalAddressDoTest();
			Assert::IsTrue(ret == 0);
        }

        TEST_METHOD(KeyRingTest)
        {
            int ret = KeyRingDoTest();
            Assert::IsTrue(ret == 0);
        }

        TEST_METHOD(Base64Test)
        {
            int ret = Base64DoTest();
            Assert::IsTrue(ret == 0);
        }

        TEST_METHOD(PeerDiscoveryTest)
        {
            int ret = PeerDiscoveryDoTest();
            Assert::IsTrue(ret == 0);
        }

        TEST_METHOD(DhGenTest)
        {
            int ret = DhGenDoTest();
            Assert::IsTrue(ret == 0);
        }
    };
}