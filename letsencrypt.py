#!/usr/bin/env python
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen, Request # Python 3
except ImportError:
    from urllib2 import urlopen, Request # Python 2

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, set_acme_callback, log=LOGGER, CA=DEFAULT_CA, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None):
    directory, acct_headers, alg, jwk = None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        while True:
            result, _, _ = _do_request(url, err_msg=err_msg)
            if result['status'] in pending_statuses:
                time.sleep(2)
                continue
            return result

    # parse account key to get public key
    log.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    log.info("Parsing CSR...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info("Found domains: {0}".format(", ".join(domains)))

    # get the ACME directory of urls
    log.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _do_request(auth_url, err_msg="Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        set_acme_callback(token, keyauthorization)

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
        log.info("{0} verified!".format(domain))

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _ = _do_request(order['certificate'], err_msg="Certificate download failed")
    log.info("Certificate signed!")
    return certificate_pem

import time
import os
import os.path
import subprocess
import threading
import socket
import BaseHTTPServer

LETS_ENCRYPT_INTER = """
-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAJgT9HUT5XULQ+dDHpceRL0wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjMzMzZaFw0yMDEwMTkyMjMzMzZa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJzTDPBa5S5Ht3JdN4OzaGMw6tc1Jhkl4b2+NfFwki+3uEtB
BaupnjUIWOyxKsRohwuj43Xk5vOnYnG6eYFgH9eRmp/z0HhncchpDpWRz/7mmelg
PEjMfspNdxIknUcbWuu57B43ABycrHunBerOSuu9QeU2mLnL/W08lmjfIypCkAyG
dGfIf6WauFJhFBM/ZemCh8vb+g5W9oaJ84U/l4avsNwa72sNlRZ9xCugZbKZBDZ1
gGusSvMbkEl4L6KWTyogJSkExnTA0DHNjzE4lRa6qDO4Q/GxH8Mwf6J5MRM9LTb4
4/zyM2q5OTHFr8SNDR1kFjOq+oQpttQLwNh9w5MCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUqEpqYwR93brm0Tm3
pkVl7/Oo7KEwDQYJKoZIhvcNAQELBQADggEBANHIIkus7+MJiZZQsY14cCoBG1hd
v0J20/FyWo5ppnfjL78S2k4s2GLRJ7iD9ZDKErndvbNFGcsW+9kKK/TnY21hp4Dd
ITv8S9ZYQ7oaoqs7HwhEMY9sibED4aXw09xrJZTC9zK1uIfW6t5dHQjuOWv+HHoW
ZnupyxpsEUlEaFb+/SCI4KCSBdAsYxAcsHYI5xxEI4LutHp6s3OT2FuO90WfdsIk
6q78OMSdn875bNjdBYAqxUp2/LEIHfDBkLoQz0hFJmwAbYahqKaLn73PAAm1X2kj
f1w8DdnkabOLGeOVcj9LQ+s67vBykx4anTjURkbqZslUEUsn2k5xeua2zUk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAMODTJjAvWslLKN5tm+lKw4wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjM1MDFaFw0yMDEwMTkyMjM1MDFa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOEkdEJ7t5Ex2XP/OKrYzkRctzkK3ESuDb1FuZc3Z6+9UE9f
0xBUa/dB2o5j5m1bwOhAqYxB/NEDif9iYQlg1gcFeJqQvRpkPk/cz3cviWvLZ69B
TcWNAMBr/o2E3LXylTGo6PaQoENKk3Rcsz5DaUuJIkd0UT6ZZMPNJAH5hC8odxci
p93DbAhMZi83dMVvk46wRjcWYdFQmMiwD09YU3ys9totlmFQrUPcCqZPnrVSuZyO
707fRrMx3CD8acKjIHU+7DgbNk5mZtLf9Wakky97pg6UPmA9Skscb7q0TRw8kVhu
L03E2nDb7QE5dsBJ5+k1tRQGkMHlkuIQ/Wu5tIUCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUxbGrTkyxzWQwk37B
hJkFq+YD4iUwDQYJKoZIhvcNAQELBQADggEBAAcSAhaE7rvHxyUnhgkEpMR56o2I
IH+mlw5kknjhAuvaBIAM59MZkFbFg5CrNWt8K+G3UoxJgFwv7HvJJxqwgPpNgXC/
uT3prkvwt+2lvzKJKbqdH+lo40P8EuSyyJOz2hjrRzNMHbJHYDS9OhF5WC5LOQQa
ydgLZ/JHxXgJypEZqcmVgQ+yYBs0XPwXjE7OE8vbx5REwu7gToMIqAoWRoWW2MxS
g28RGPVnHzHk2XV1nZGy9T+NYQ91vWWJr1pzNEFZ0cnA2xGwTeJ+zZ3URCfw3Z1U
+YAL3YUmrvdoRBlASOTmNJmXSo9qvMYPa3DEomAPoFQFZqsSN6kuqDEIqMA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc6bLEeMfizANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDEwMloXDTIxMDMxNzE2NDEwMlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFg0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4SR0Qnu3kTHZc/84qtjORFy3OQrcRK4NvUW5lzdnr71QT1/T
EFRr90HajmPmbVvA6ECpjEH80QOJ/2JhCWDWBwV4mpC9GmQ+T9zPdy+Ja8tnr0FN
xY0AwGv+jYTctfKVMajo9pCgQ0qTdFyzPkNpS4kiR3RRPplkw80kAfmELyh3FyKn
3cNsCExmLzd0xW+TjrBGNxZh0VCYyLAPT1hTfKz22i2WYVCtQ9wKpk+etVK5nI7v
Tt9GszHcIPxpwqMgdT7sOBs2TmZm0t/1ZqSTL3umDpQ+YD1KSxxvurRNHDyRWG4v
TcTacNvtATl2wEnn6TW1FAaQweWS4hD9a7m0hQIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBTFsatOTLHNZDCTfsGEmQWr5gPiJTANBgkqhkiG9w0BAQsF
AAOCAQEANlaeSdstfAtqFN3jdRZJFjx9X+Ob3PIDlekPYQ1OQ1Uw43rE1FUj7hUw
g2MJKfs9b7M0WoQg7C20nJY/ajsg7pWhUG3J6rlkDTfVY9faeWi0qsPYXE6BpBDr
5BrW/Xv8yT8U2BiEAmNggWq8dmFl82fghmLzHBM8X8NZ3ZwA1fGePA53AP5IoD+0
ArpW8Ik1sSuQBjZ8oQLfN+G8OoY7MNRopyLyQQCNy4aWfE+xYnoVoa5+yr+aPiX0
7YQrY/cKawAn7QB4PyF5//IKSAVs7mAuB68wbMdE3FKfOHfJ24W4z/bIJTrTY8Y5
Sr4AUhtzf8oVDrHZYWRrP4joIcOu/Q==
-----END CERTIFICATE-----"""

OPENSSL_CONF_PATH = 'openssl.cnf'
OPENSSL_CONF = """#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME			= .
RANDFILE		= $ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file		= $ENV::HOME/.oid
oid_section		= new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions		= 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=${testoid1}.5.6

# Policies used by the TSA examples.
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

dir		= /etc/ssl		# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
#unique_subject	= no			# Set to 'no' to allow creation of
					# several ctificates with same subject.
new_certs_dir	= $dir/newcerts		# default place for new certs.

certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem# The private key
RANDFILE	= $dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extentions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

# Extension copying option: use with caution.
# copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crlnumber must also be commented out to leave a V1 CRL.
# crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= AU
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

# SET-ex3			= SET extension number 3

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This is required for TSA certificates.
# extendedKeyUsage = critical,timeStamping

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = %s

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

# These are used by the TSA reply generation only.
dir		= ./demoCA		# TSA root directory
serial		= $dir/tsaserial	# The current serial number (mandatory)
crypto_device	= builtin		# OpenSSL engine to use for signing
signer_cert	= $dir/tsacert.pem 	# The TSA signing certificate
					# (optional)
certs		= $dir/cacert.pem	# Certificate chain to include in reply
					# (optional)
signer_key	= $dir/private/tsakey.pem # The TSA private key (optional)

default_policy	= tsa_policy1		# Policy if request did not specify it
					# (optional)
other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
digests		= md5, sha1		# Acceptable message digests (mandatory)
accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
clock_precision_digits  = 0	# number of digits after dot. (optional)
ordering		= yes	# Is ordering defined for timestamps?
				# (optional, default: no)
tsa_name		= yes	# Must the TSA name be included in the reply?
				# (optional, default: no)
ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
				# (optional, default: no)
"""

acme_token = None
acme_authorization = None

class ServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_text_response(self, text, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        self.wfile.write(text)
        self.wfile.close()

    def do_GET(self):
        try:
            if not self.path.startswith('/.well-known/acme-challenge/'):
                self.send_response(404)
                return

            token = self.path.split('/.well-known/acme-challenge/')[-1]
            if token != acme_token:
                self.send_response(404)
                return

            self.send_text_response(acme_authorization, 200)
        except:
            self.send_response(500)

class HTTPServer6(BaseHTTPServer.HTTPServer):
    address_family = socket.AF_INET6

def set_acme(token, authorization):
    global acme_token
    global acme_authorization
    acme_token = token
    acme_authorization = authorization

def generate_account_key():
    return subprocess.check_output([
        'openssl', 'genrsa', '4096',
    ]).rstrip('\n') + '\n'

def generate_private_key():
    return subprocess.check_output([
        'openssl', 'genrsa', '2048',
    ]).rstrip('\n') + '\n'

def generate_private_ec_key():
    return subprocess.check_output([
        'openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout',
    ]).rstrip('\n') + '\n'

def generate_csr(private_key_path, domains):
    if len(domains) == 1:
        return subprocess.check_output([
            'openssl',
            'req',
            '-new',
            '-batch',
            '-sha256',
            '-key', private_key_path,
            '-subj', '/CN=%s' % domains[0],
        ])

    subject = ','.join(['DNS:' + x for x in domains])

    with open(OPENSSL_CONF_PATH, 'w') as cnf_file:
        cnf_file.write(OPENSSL_CONF % subject)

    csr = subprocess.check_output([
        'openssl',
        'req',
        '-new',
        '-batch',
        '-sha256',
        '-config', OPENSSL_CONF_PATH,
        '-key', private_key_path,
    ])

    os.remove(OPENSSL_CONF_PATH)

    return csr

def get_acme_cert(account_key_path, csr_path):
    return get_crt(
        account_key_path,
        csr_path,
        set_acme,
    )

def run_server():
    server = HTTPServer6(
        ('::', 80),
        ServerHandler,
    )
    server.serve_forever()

def get_cert(domains):
    ec_key = True
    if domains[0] == '--rsa':
        ec_key = False
        domains.pop(0)

    print domains

    private_key_path = domains[0] + '.key'
    account_key_path = domains[0] + '.account'
    csr_path = domains[0] + '.csr'
    certificate_path = domains[0] + '.cert'
    pem_path = domains[0] + '.pem'

    if not os.path.isfile(private_key_path):
        if ec_key:
            private_key = generate_private_ec_key()
        else:
            private_key = generate_private_key()
        with open(private_key_path, 'w') as private_key_file:
            os.chmod(private_key_path, 0600)
            private_key_file.write(private_key)
    else:
        with open(private_key_path, 'r') as private_key_file:
            private_key = private_key_file.read().rstrip('\n') + '\n'

    if not os.path.isfile(account_key_path):
        account_key = generate_account_key()
        with open(account_key_path, 'w') as account_key_file:
            os.chmod(account_key_path, 0600)
            account_key_file.write(account_key)

    csr = generate_csr(private_key_path, domains)
    with open(csr_path, 'w') as csr_file:
        csr_file.write(csr)

    thread = threading.Thread(target=run_server)
    thread.daemon = True
    thread.start()

    time.sleep(0.5)

    certificate = get_acme_cert(
        account_key_path, csr_path).rstrip('\n') + LETS_ENCRYPT_INTER
    with open(certificate_path, 'w') as certificate_file:
        certificate_file.write(certificate)

    with open(pem_path, 'w') as pem_file:
        os.chmod(pem_path, 0600)
        pem_file.write(private_key)
        pem_file.write(certificate)

    os.remove(csr_path)

get_cert(sys.argv[1:])
