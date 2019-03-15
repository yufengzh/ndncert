/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "crypto-helper.hpp"
#include "../logging.hpp"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/step-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/hmac-filter.hpp>

namespace ndn {
namespace ndncert {

const size_t HASH_SIZE = 32;

_LOG_INIT(crypto-support);

ECDHState::ECDHState()
{
  OpenSSL_add_all_algorithms();
  context = std::make_unique<ECDH_CTX>();
  context->EC_NID = NID_X9_62_prime256v1;

  // Create the context for parameter generation
  if (nullptr == (context->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr))) {
    handleErrors("Could not create context contexts.");
    return;
  }

  // Initialise the parameter generation
  if (EVP_PKEY_paramgen_init(context->ctx_params) != 1) {
    handleErrors("Could not initialize parameter generation.");
    return;
  }

  // We're going to use the ANSI X9.62 Prime 256v1 curve
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context->ctx_params, context->EC_NID)) {
    handleErrors("Likely unknown elliptical curve ID specified.");
    return;
  }

  // Create the parameter object params
  if (!EVP_PKEY_paramgen(context->ctx_params, &context->params)) {
    // the generated key is written to context->params
    handleErrors("Could not create parameter object parameters.");
    return;
  }

  // Create the context for the key generation
  if (nullptr == (context->ctx_keygen = EVP_PKEY_CTX_new(context->params, nullptr))) {
    //The EVP_PKEY_CTX_new() function allocates public key algorithm context using
    //the algorithm specified in pkey and ENGINE e (in this case nullptr).
    handleErrors("Could not create the context for the key generation");
    return;
  }

  // initializes a public key algorithm context
  if (1 != EVP_PKEY_keygen_init(context->ctx_keygen)){
    handleErrors("Could not init context for key generation.");
    return;
  }
  if (1 != EVP_PKEY_keygen(context->ctx_keygen, &context->privkey)) {
    //performs a key generation operation, the generated key is written to context->privkey.
    handleErrors("Could not generate DHE keys in final step");
    return;
  }
}

ECDHState::~ECDHState()
{
  // Contexts
  if(context->ctx_params != nullptr){
    EVP_PKEY_CTX_free(context->ctx_params);
  }
  if(context->ctx_keygen != nullptr){
    EVP_PKEY_CTX_free(context->ctx_keygen);
  }

  // Keys
  if(context->privkey != nullptr){
    EVP_PKEY_free(context->privkey);
  }
  if(context->peerkey != nullptr){
    EVP_PKEY_free(context->peerkey);
  }
  if(context->params != nullptr){
    EVP_PKEY_free(context->params);
  }
}

uint8_t*
ECDHState::getRawSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);

  if (privECKey == NULL) {
    handleErrors("Could not get referenced key when calling EVP_PKEY_get1_EC_KEY().");
    return NULL;
  }

  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  const EC_GROUP* group = EC_KEY_get0_group(privECKey);
  context->publicKeyLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_COMPRESSED,
                                             context->publicKey, 256, nullptr);
  if (context->publicKeyLen == 0) {
    handleErrors("Could not convert EC_POINTS to octet string when calling EC_POINT_point2oct.");
    return NULL;
  } 

  return context->publicKey;
}

std::string
ECDHState::getBase64PubKey()
{
  if (context->publicKeyLen == 0) {
    this->getRawSelfPubKey();
  }
  std::stringstream os;
  security::transform::bufferSource(context->publicKey, context->publicKeyLen)
    >> security::transform::base64Encode() >> security::transform::streamSink(os);
  return os.str();
}

uint8_t*
ECDHState::deriveSecret(const uint8_t* peerkey, int peerKeySize)
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);

  if (privECKey == NULL) {
    handleErrors("Could not get referenced key when calling EVP_PKEY_get1_EC_KEY().");
    return NULL;
    }

  auto group = EC_KEY_get0_group(privECKey);
  auto peerPoint = EC_POINT_new(group);
  EC_POINT_oct2point(group, peerPoint, peerkey, peerKeySize, nullptr);

  if (0 == (context->sharedSecretLen = ECDH_compute_key(context->sharedSecret, 256,
                                                        peerPoint, privECKey, nullptr)))
    handleErrors("Cannot generate ECDH secret with ECDH_compute_key");
  return context->sharedSecret;
}

uint8_t*
ECDHState::deriveSecret(const std::string& peerKeyStr)
{
  namespace t = ndn::security::transform;
  OBufferStream os;
  security::transform::bufferSource(peerKeyStr)
    >> security::transform::base64Decode() >> security::transform::streamSink(os);
  ConstBufferPtr result = os.buf();
  return this->deriveSecret(result->data(), result->size());
}

//ndn_compute_hmac_sha256 is the wrapper of ndn-cxx implementation of hmac_sha256.
//Implemented this for hkdf to more conveniently access hmac_sha256 value.
static Buffer ndn_compute_hmac_sha256 (const uint8_t *data, const unsigned  data_length,
                                    const uint8_t *key, const unsigned key_length) {
  OBufferStream os;
  
  security::transform::bufferSource(data, data_length) >>
    security::transform::hmacFilter(DigestAlgorithm::SHA256, key, key_length) >>
    security::transform::streamSink(os);
  
  auto result = os.buf();
  return *result;
}

//removed dependency of OpenSSL@1.1
int
hkdf(const uint8_t* secret, int secretLen, const uint8_t* salt,
     int saltLen, uint8_t* result, int resultMaxLen)
{
  //uint8_t tmp[resultMaxLen];
  uint8_t *tmp = new uint8_t[resultMaxLen];

  // hkdf generate prk
  uint8_t *prk = ndn_compute_hmac_sha256(secret, secretLen, salt, saltLen).data(), *T;
  uint8_t outlen = HASH_SIZE, i, n, tmplen;
  uint8_t *p;

  // hkdf expand 
    n = resultMaxLen / HASH_SIZE;
    if (resultMaxLen % HASH_SIZE) n++;

    tmplen = outlen;

    for (i = 0; i < n; i++) {
        p = tmp;

        //T(0) = empty string
        if (i != 0) {
            memcpy(p, T, HASH_SIZE);
            p += HASH_SIZE;
        }
        memcpy(p, "label", 5);

        p += 1; // "label" and 5 will be replaced by configs in config file
        *p++ = i + 5;

        T = ndn_compute_hmac_sha256(tmp, (int)(p - tmp), prk, HASH_SIZE).data();
        memcpy(result + i * HASH_SIZE, T, tmplen < HASH_SIZE ? tmplen : HASH_SIZE);
        tmplen -= HASH_SIZE;
    }
    return outlen;
}

void
handleErrors(const std::string& errorInfo)
{
  _LOG_DEBUG("Error in CRYPTO SUPPORT " << errorInfo);
  BOOST_THROW_EXCEPTION(CryptoError("Error in CRYPTO SUPPORT: " + errorInfo));
  return;
}

} // namespace ndncert
} // namespace ndn
