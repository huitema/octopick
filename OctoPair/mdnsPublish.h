#pragma once

/*
 * Listen to IPv6 multicast port
 *  - Bind to IPv6 local address on selected interface
 *
 * MDNS Publisher for the Pairing and Private Discovery protocols
 *   - By default, always publish with the preferred local IPv6 address.
 *
 * Always publish the AAAA record for the randomized host name.
 * If Pairing is enabled: publish the PTR record for the pairing protocol, 
 * using the chosen instance name.
 *   - The instance name can be either the subject name (Daniel) or 
 *     anonymous, in which case the host name is used.
 *   - Specify the local pairing port in all cases.
 * If Private Discovery is enabled:
 *   - Use pairing context to obtain the list of current pairings
 *   - On demand, compute the corresponding instance name using SHA256 and BASE64
 *   - Publish PTR records, SRV records, empty TXT record on demand.
 *   - Use private discovery port for publication
 */