#pragma once

/*
 * Declaration of test cases.
 * The declarations do not pull any external dependencies, so as 
 * to minimize compile time requirements for the test harnesses.
 */
#ifdef __cplusplus
extern "C" {
#endif
    /* Test procedures */
	int LocalAddressDoTest();
    int KeyRingDoTest();
    int Base64DoTest();
    int PeerDiscoveryDoTest();

#ifdef __cplusplus
}
#endif