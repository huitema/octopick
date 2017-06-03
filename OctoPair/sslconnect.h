#ifndef SSLCONNECT_H
#define SSLCONNECT_H

#ifdef __cplusplus
extern "C" {
#endif
    /*
     * Generating long keys will take a very long time, maybe 1 hour for l=2048
     */
    DH * create_dh_key(unsigned int length_in_bits);

#ifdef __cplusplus
}
#endif

#endif /* SSLCONNECT_H */
