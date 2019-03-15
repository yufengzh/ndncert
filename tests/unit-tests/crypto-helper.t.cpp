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

#include "crypto-support/crypto-helper.hpp"
#include "test-common.hpp"
#include <iostream>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestCryptoHelper)

BOOST_AUTO_TEST_CASE(Test0)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getRawSelfPubKey();
  BOOST_CHECK(aliceState.context->publicKeyLen != 0);

  ECDHState bobState;
  auto bobPub = bobState.getRawSelfPubKey();
  BOOST_CHECK(bobState.context->publicKeyLen != 0);

  auto aliceResult = aliceState.deriveSecret(bobPub, bobState.context->publicKeyLen);
  BOOST_CHECK(aliceState.context->sharedSecretLen != 0);

  auto bobResult = bobState.deriveSecret(alicePub, aliceState.context->publicKeyLen);
  BOOST_CHECK(bobState.context->sharedSecretLen != 0);

  BOOST_CHECK_EQUAL_COLLECTIONS(aliceResult, aliceResult + 32,
                                bobResult, bobResult + 32);
}

BOOST_AUTO_TEST_CASE(Test1)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getBase64PubKey();
  BOOST_CHECK(alicePub != "");

  ECDHState bobState;
  auto bobPub = bobState.getBase64PubKey();
  BOOST_CHECK(bobPub != "");

  auto aliceResult = aliceState.deriveSecret(bobPub);
  BOOST_CHECK(aliceState.context->sharedSecretLen != 0);

  auto bobResult = bobState.deriveSecret(alicePub);
  BOOST_CHECK(bobState.context->sharedSecretLen != 0);

  BOOST_CHECK_EQUAL_COLLECTIONS(aliceResult, aliceResult + 32,
                                bobResult, bobResult + 32);
}

BOOST_AUTO_TEST_CASE(Test2)
{
  uint8_t secret[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t result[32];
  auto resultLen = hkdf(secret, sizeof(secret), salt, sizeof(salt),result, 32);
  BOOST_CHECK(resultLen != 0);
}

BOOST_AUTO_TEST_CASE(Test3)
{
  uint8_t secret[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t result[32];
  uint8_t expected[] = {0xf2,0x5d,0xb6,0xc5,0xbe,0xa6,0xff,0xb2,0xa2,0x02,0xe1,0x4d,0x43,0x30,0x7c,0xa2,0x4e,0x2c,0xb1,0xf9,0x4b,0x94,0xd0,0x70,0x93,0x33,0x39,0x6b,0x5e,0x7c,0x71,0x96};

  auto resultLen = hkdf(secret, sizeof(secret), salt, sizeof(salt),result, 32);
  printf("resultLen from hkdf:%d\n",resultLen);
  for(int i=0;i<32;i++)
  printf("0x%02x,", result[i]);
  printf("\n");
  BOOST_CHECK(resultLen != 0);
  BOOST_CHECK(memcmp(expected, result, 32) == 0);
}

BOOST_AUTO_TEST_CASE(Test4)
{
  uint8_t secret[] = {0xe0,0x4b,0x5a,0x9c,0x3c,0x23,0x24,0xb9,0x2f,0x98,
                     0xcf,0xd4,0x10,0x48,0xdc,0x66,0x3a,0xe4,0x9d,0xaf};

  uint8_t salt[] = {0x6b,0xf9,0x49,0x8b,0xfd,0x7c,0x3f,0xbd,0x38,0xb0,
                    0xf7,0x42,0xc1,0xda,0xcf,0x2a,0x9c,0x24,0x92,0x80,
                    0x83,0xd2,0x67,0x2b,0xf1,0xfc,0xea,0xc4,0x21,0x24};

  uint8_t result[32];
  uint8_t expected[] = {0x3f,0x1c,0xf4,0x4a,0x74,0x1d,0x63,0x33,0x54,0x7a,0x2c,0x7d,0x4e,0x3a,0xda,0x85,0x4b,0x56,0xf1,0x12,0x5e,0xc3,0x5e,0x31,0x30,0xc9,0xbb,0x26,0xf9,0x0f,0x75,0xbb};
  auto resultLen = hkdf(secret, sizeof(secret), salt, sizeof(salt),result, 32);
  printf("resultLen from hkdf:%d\n",resultLen);
  for(int i=0;i<32;i++)
  printf("0x%02x,", result[i]);
  printf("\n");


  BOOST_CHECK(resultLen != 0);
  BOOST_CHECK(memcmp(expected, result, 32) == 0);
}

BOOST_AUTO_TEST_CASE(Test5)
{
  uint8_t secret[] = {0x86,0xff,0xbb,0xf9,0xfc,0x55,0x7c,0xa6,0x57,0xcd,0xd1,0x07,0x2d,0x98,0x9f,0x38,0x78,0xc5,0x36,0xe7,0xcc,0xa8,0x95,0x6e,0x0f,0x96,0xb9,0xf6,0x7a,0xe5,0x90,0xe1,0xad,0x2c,0xb8,0x4f,0x22,0xcd,0x62,0x5d,0xce,0xdc,0xed,0xfa,0x7c,0xa6,0xe2,0x51,0x27,0x28,0xc8,0x7c,0x7e,0x0d,0x50,0x65,0x6d,0x03,0xc1,0xb8,0x46,0x81,0x82,0xbf,0x81,0xc4,0xa6,0xd1,0x10,0xa9,0xde,0x59,0xc8,0x42,0x81,0xc2,0xd6,0x59,0x37,0x02,0xa3,0x70,0xee,0x12,0xe7,0xeb,0xf7,0x42,0x75,0xcb,0x77,0x7b,0xba,0x97,0x9b,0x38,0x8a,0x9e,0xa3,0x4e,0xfb,0xb0,0xfc,0xb4,0x82,0x09,0x8b,0xf8,0x01,0x4d,0x98,0x37,0x94,0x00,0x0a,0xb5,0x77,0xf5,0x7b,0xa3,0x48,0x86,0xe6,0xfa,0x9c,0xbd,0xae,0x23,0x50,0x7c,0xc7,0x7c,0xed,0x43,0x4b,0x39,0x27,0x61,0xc5,0x57,0x71,0xa2,0xf7,0x96,0xeb,0x16,0x82,0x7a,0xd0,0xd1,0xfe,0x27,0xc8,0x8f,0x08,0x94,0x0b,0xa7,0x14,0x13,0xd1,0xe7,0xa4,0xd3,0x3e,0x12,0x4c,0x54,0xdb,0xa8,0x4a,0x3b,0x8b,0x9f,0x29,0x6f,0x99,0x54,0x9d,0xb9,0xf1,0x69,0x39,0x5f,0x32,0x83,0x39,0xeb,0xcd,0x23,0x66,0x0f,0x3e,0x58,0x91,0x7d,0xd9,0x8a,0xfc,0x8f};

  uint8_t salt[] = {0x9f,0x46,0x5e,0xfb,0xba,0xd9,0xb5,0x17,0x7e,0x0b,0x86,0x3a,0xed,0xfa,0x7e,0x70,0x02,0x1c,0x75,0x63,0x06,0x80,0x7e,0xfe,0x32,0x2c,0x3a,0x8a,0xd0,0x0d,0xac,0xfa,0xa1,0xdf,0xa7,0x1c,0xaf,0xdb,0x8b,0x68,0x64,0x82,0xfd,0xc9,0xc1,0x79,0x0d,0x3e,0x93,0x35,0x04,0x05,0x7d,0xd2,0x02,0x0d,0x38,0x1c,0xdd,0xb5,0x7a,0x1d,0x53,0x25,0x55,0xaa,0x6d,0xe5,0x62,0x22,0x96,0x10,0xaf,0x4f,0x6b,0x55,0xda,0x58,0xdc,0x1a,0x1c,0xbb,0x0b,0x02,0xf0,0xd8,0x88,0xea,0xb4,0xc9,0x77,0x3f,0xaa,0x69,0x93,0x7c,0xd7,0x6d,0x3a,0x6e,0x78,0x83,0x7a,0x57,0x77,0x46,0x21,0xd2,0x20,0xc2,0x82,0x2d,0x09,0xcf,0x5b,0x67,0xa9,0x80,0x6e,0x4b,0x4a,0x2b,0xe1,0x81,0x88,0x5b,0x5d,0x73,0x53,0xb5,0xb9,0x3d,0xa5,0xb8,0x13,0xda,0xb9,0xc1,0xb9,0x25,0x07,0xab,0x75,0xf4,0x15,0xea,0x89,0xdd,0x86,0x04,0x5c,0x3e,0xf5,0x36,0x67,0xd3,0x93,0x7b,0x06,0x49,0xa6,0x49,0x46,0xc0,0x56,0xdd,0x83,0xf1,0x9c,0xc2,0xb5,0xc3,0x14,0x4b,0x42,0x22,0x5c,0x8f,0x1f,0xdb,0xfc,0x28,0xcc,0x7f,0xe3,0x81,0x0f,0x04,0x7f,0xa4,0x80,0x20,0xc5,0x9c,0xb4,0x0a,0xc2,0xa6,0xef,0x40,0x73,0xb4,0x88,0x08,0xba,0xca,0x2d,0x1c,0x8b,0x76,0x82,0x7a,0x40,0x69,0x94,0xfb,0x88,0x9c,0xaf,0x91,0xf7,0x9c,0x93,0x11,0xeb,0xf8,0x9e,0x81,0x72,0x41,0x11,0xe9,0x8f,0x37,0x59,0x49,0xf8,0x3b,0xea,0x05,0x9d,0x89,0x13,0x98,0x25,0x93,0x8b,0x8c,0x4c,0x0d,0x8e,0x16,0x3b,0x01,0xe8,0xe9,0x3f,0xa5,0x87,0x95,0x0f,0x21,0x34,0xae,0xd5,0xe6,0x74,0x40,0x48,0x2b,0x95,0xa7,0xfc,0x30,0xe8,0xb6,0x88,0x8a,0x4f,0xc9,0xc7,0x0a,0x1b,0x6a,0x7e,0xcb,0x83,0x2c,0xfa,0xce,0x30,0xb7,0x80,0xb8,0x54,0xe1,0xbe,0xad,0xf2,0xd2,0xd7,0x00,0x53,0x73,0xb9,0x87,0x77,0x33,0x0f,0x08,0x86,0xbc,0xa4,0xaf,0x80,0x93,0xb5,0x1f,0x3a,0x88,0xc4,0x5f,0xe5,0xeb,0x24,0x61,0xec,0x9e,0x60,0x9c,0x42,0x32,0x5f,0xa2,0x69,0xd7,0x9d,0x1b,0x20,0x40,0x3a,0xaf,0xe0,0x39,0x2c,0xad,0x07,0x82,0x51,0x67,0xe3,0xb3,0x1b,0x11,0xf7,0xf5,0x79,0x45,0x72,0x37,0x86,0xa7,0xcb,0x61,0x10,0x77,0xd6,0x2a,0xa9,0xb9,0x14,0xda,0x51,0xfd,0x94,0xdd,0x15,0xb3,0x45,0x42,0x7b,0xec,0x4f,0x76,0x42,0xac,0x6c,0x57,0x11,0x14,0x56,0x37,0x05,0x22,0x01,0xf3,0xe9,0x40,0xd0,0x85,0x83,0xc7,0x75,0xe1,0xf3,0x17,0xf8,0x8e,0xf2,0x89,0x14,0x82,0x99,0x4c,0x41,0x38,0x47,0xd4,0x65,0x66,0x08,0xe1,0x1e,0xe9,0x10,0x38,0x0f,0x9f,0xe8,0x87,0x16,0xdc,0x4e,0x5a,0xdc,0x6a,0xf4,0xc0,0xa7,0x56,0x1f,0xab,0x0f,0x0a,0x55,0x81,0xbd,0xb3,0xa6,0xbe,0xc4,0x13,0x97,0x69,0x0c,0xae,0x28,0x06,0x87,0xff,0xdc,0xc2,0x3f,0xa2,0xad,0x07,0x8d,0x54,0x0b,0x02,0xa1,0x06,0x8c,0x72,0xf5,0x7a,0xfc,0xfc,0x10,0xeb,0x12,0xbf,0x7c,0xb3,0xb8,0xb8,0x14,0x2a,0x69,0xaf,0x24,0x30,0x7f,0x4c,0xc8,0x8e,0xb5,0x33,0xb9,0xed,0x38,0xd5,0xe7,0x13,0x96,0x29,0x93,0x09,0x9c,0x80,0x0c,0x7b,0x0a,0xd9,0xea,0x80,0xee,0xd8,0xc8,0xe1,0x80,0x51,0x91,0xbb,0x15,0xbe,0xbe,0x65,0xc7,0xb4,0xdb,0xcb,0x70,0x2f,0x5e,0x14,0x69,0xf8,0xa4,0xdb,0x5c,0xda,0xbb,0xdc,0xfe,0xe1,0xd8,0x1e,0x28,0x31,0xc2,0x8b,0x7e,0xd7,0x7d,0x76,0x8f,0xfa,0x83,0x43,0x97,0xcf,0x95,0x8f,0x03,0xa7,0xba,0x5a,0xae,0x37,0x28,0xef,0xb3,0x92,0x65,0x0e,0x35,0x6e,0x0e,0x31,0xbc,0x56,0xc6,0x21,0x08,0x9e,0xb1,0x52,0x84,0xd3,0x41,0xe7,0x05,0x62,0xa1,0x0d,0x6a,0xc1,0x4b,0xca,0xfc,0xac,0xee,0xf4,0x10,0x90,0xe1,0xcb,0x81,0xb1,0x4d,0x16,0x46,0x91,0x08,0x4e,0x5d,0xcd,0xc0,0xe4,0x3b,0x07,0x76,0xdd,0x53,0x3b,0xbe,0xd2,0xd4,0xce,0xe2,0x84,0xf4,0x99,0x69,0x66,0xef,0xb5,0x4b,0xb6,0x4a,0x07,0x61,0x0f,0xbb,0x50,0xdc,0x40,0x71,0x3f,0x6d,0x4b,0xdf,0x05,0x66,0x57,0x31,0xb5,0xde,0x53,0xdb,0x1b,0x84,0x4d,0x5c,0xee,0x22,0xa5,0xa3,0x9f,0x86,0xe4,0xa0,0x9b,0xb1,0x18,0x4b,0xbf,0x11,0x67,0x68,0x39,0xfe,0xcd,0x59,0xac,0x87,0x90,0x5e,0x9a,0x01,0x32,0xb0,0x64,0x07,0x68,0xf8,0x13,0x55,0xc4,0x55,0x33,0xb3,0xdd,0x46,0x15,0x85,0xa6,0x88,0xc2,0x7e,0x00,0x8a,0xa6,0x1a,0xc2,0x8d,0xf8,0xed,0xbe,0xa5,0xa2,0x54,0x13,0xbd,0x2f,0x5d,0xc6,0x60,0x08,0x7d,0xad,0x3e,0x9b,0x71,0xfc,0x16,0xdb,0x44,0x95,0x1e,0x7d,0xbf,0x38,0x1e,0xc8,0x0a,0x0a,0xbd,0x95,0x22,0xff,0x1c,0x7d,0x08,0x83,0x63,0xb1,0x16,0xa6,0xd5,0x56,0xe2,0x91,0xce,0xad,0x5c,0xd1,0x83,0xf2,0x35,0x18,0xa3,0xc0,0xd0,0x20,0x1c,0x2a,0xf6,0x80,0x2c,0x62,0x66,0xe8,0x5f,0x79,0xc7,0x7e,0x11,0x2a,0xc5,0x43,0x09,0x3f,0xa9,0x31,0x2f,0x71,0xad,0xd3,0xf8,0x73,0xca,0x1a,0xdd,0x42,0xe0,0x78,0x8f,0x25,0x2a,0x2c,0x40,0xfe,0x98,0xc3,0x51,0xed,0xb5,0x5a,0xaf,0x09,0xb9,0x07,0x97,0x37,0xe2,0x36,0x16,0xb9,0x6e,0xab,0xe9,0x24,0x4d,0x35,0x7f,0x38,0x68,0xe9,0x96,0xe4,0x39,0xdc,0x0a,0x54,0x2a,0x5a,0x34,0x59,0x78,0xed,0x31,0x13,0x8c,0x55,0x44,0xc4,0xb2,0x32,0x9e,0xe6,0x3c,0x61,0x75,0x06,0xbf,0xca,0x62,0xb5,0x98,0xc7,0xc5,0xb9,0xe3,0xd0,0x02,0xb7,0x05,0x32,0xa7,0x53,0xd5,0xf8,0x54,0x8c,0xf9,0x36,0xbb,0x0c,0x1a,0x73,0x6c,0xc9,0xcf,0x35,0x21,0x16,0x6f,0x4d,0xd6,0x59,0xa1,0x31,0x8b,0x60,0x42,0x79,0xa2,0x71,0xf8,0xf2,0xb3,0x8a,0x4d,0x20,0x7a,0x0b,0xbe,0xed,0x73,0x15,0x41,0x16,0x54,0x71,0x88,0x8c,0x10,0xaf,0x1b,0xc8,0x36,0x44,0x26,0xf0,0xe8,0x88,0xc4,0x6e,0xeb,0xf7,0xab,0xd5,0xb6,0xe4,0x11,0xe1,0xf4,0x0b,0x6d,0xa1,0x0f,0xfe,0xb0,0x4f,0xaa,0x18,0x27,0xbe,0x0d,0xb3,0xf7,0x09,0xe7,0xe5,0x46,0xd9,0x1a,0xc1,0x11,0x73,0x6a,0xe3,0x80,0x2d,0xf8,0xc1,0xe5,0x33,0xc1,0xfc,0x70,0x93,0x3a,0xdf,0xf4,0x9c,0x02,0x67,0x7a,0x90,0xee,0xed,0x9c,0x2d,0x9b,0xe8,0x90,0x6d};

  uint8_t result[32];
  uint8_t expected[] = {0x19,0x27,0xe3,0x24,0xb7,0xca,0x58,0x0a,0xf6,0xda,0x2c,0x64,0xcc,0x20,0xe9,0xc5,0x1a,0xb3,0x5b,0xdf,0xe6,0xd2,0x44,0x54,0xfe,0xe5,0xbd,0x55,0x45,0xee,0x69,0x54};

  auto resultLen = hkdf(secret, sizeof(secret), salt, sizeof(salt),result, 32);
  BOOST_CHECK(resultLen != 0);
  printf("resultLen from hkdf:%d\n",resultLen);
  for(int i=0;i<32;i++)
  printf("0x%02x,", result[i]);
  printf("\n");
  BOOST_CHECK(memcmp(expected, result, 32) == 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn