/* 
 * Copyright (C) 2022 Dinglan Peng
 *    
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_NETTLE
#error "This header should not be compiled without HAVE_NETTLE defined"
#endif

#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <assert.h>
#include <stdexcept>

#include <nettle/bignum.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>

#include <core/LogWriter.h>
#include <core/string.h>

#include <rfb/SSecurityRSAAES.h>
#include <rfb/SConnection.h>

#include <rdr/AESInStream.h>
#include <rdr/AESOutStream.h>
#include <rdr/MemOutStream.h>
#include <rdr/RandomStream.h>

enum {
  ReadPublicKey,
  ReadRandom,
  ReadHash,
  ReadCredentials,
};

const int MinKeyLength = 1024;
const int MaxKeyLength = 8192;

using namespace rfb;

static core::LogWriter vlog("SSecurityRSAAES");

SSecurityRSAAES::SSecurityRSAAES(SConnection* sc_, uint32_t _secType,
                                 int _keySize, bool _isAllEncrypted)
  : SSecurity(sc_), state(ReadPublicKey),
    keySize(_keySize), isAllEncrypted(_isAllEncrypted), secType(_secType),
    serverKey(), clientKey(),
    serverKeyN(nullptr), serverKeyE(nullptr),
    clientKeyN(nullptr), clientKeyE(nullptr),
    rais(nullptr), raos(nullptr), rawis(nullptr), rawos(nullptr)
{
  assert(keySize == 128 || keySize == 256);
  username[0] = '\0';
  password[0] = '\0';
}

SSecurityRSAAES::~SSecurityRSAAES()
{
  cleanup();
}

void SSecurityRSAAES::cleanup()
{
  if (raos) {
    try {
      if (raos->hasBufferedData()) {
        raos->cork(false);
        raos->flush();
        if (raos->hasBufferedData())
          vlog.error("Failed to flush remaining socket data on close");
      }
    } catch (std::exception& e) {
      vlog.error("Failed to flush remaining socket data on close: %s", e.what());
    }
  }

  if (serverKeyN)
    delete[] serverKeyN;
  if (serverKeyE)
    delete[] serverKeyE;
  if (clientKeyN)
    delete[] clientKeyN;
  if (clientKeyE)
    delete[] clientKeyE;
  if (serverKey.size)
    rsa_private_key_clear(&serverKey);
  if (clientKey.size)
    rsa_public_key_clear(&clientKey);
  if (isAllEncrypted && rawis && rawos)
    sc->setStreams(rawis, rawos);
  if (rais)
    delete rais;
  if (raos)
    delete raos;
}

bool SSecurityRSAAES::processMsg()
{
  switch (state) {
    case ReadPublicKey:
      writePublicKey();
      writeRandom();
      if (!readPublicKey())
        return false;
      state = ReadRandom;
      /* fall through */
    case ReadRandom:
      if (!readRandom())
        return false;
      setCipher();
      if (!readHash())
        return false;
      writeHash();
      clearSecrets();
      writeSubtype();
      state = ReadCredentials;
      /* fall through */
    case ReadCredentials:
      if (!readCredentials())
        return false;
      return true;
  }

  throw std::logic_error("Invalid state");

  return false;
}

static void random_func(void*, size_t length, uint8_t* dst)
{
  rdr::RandomStream rs;
  if (!rs.hasData(length))
    throw std::runtime_error("Failed to generate random");
  rs.readBytes(dst, length);
}

void SSecurityRSAAES::writePublicKey()
{
  rdr::OutStream* os = sc->getOutStream();
  struct rsa_public_key pubKey;
  rsa_public_key_init(&pubKey);
  rsa_private_key_init(&serverKey);
  
  serverKeyLength = 2048; 
  if (serverKeyLength < MinKeyLength)
    serverKeyLength = MinKeyLength;
  if (serverKeyLength > MaxKeyLength)
    serverKeyLength = MaxKeyLength;
  int rsaKeySize = (serverKeyLength + 7) / 8;
  
  pubKey.size = rsaKeySize;
  serverKey.size = rsaKeySize;
  
  mpz_set_ui(pubKey.e, 65537);
  if (!rsa_generate_keypair(&pubKey, &serverKey,
                            nullptr, random_func, nullptr, nullptr,
                            serverKeyLength, 0)) {
    rsa_public_key_clear(&pubKey);
    throw std::runtime_error("Failed to generate key");
  }
  
  serverKeyN = new uint8_t[rsaKeySize];
  serverKeyE = new uint8_t[rsaKeySize];
  nettle_mpz_get_str_256(rsaKeySize, serverKeyN, pubKey.n);
  nettle_mpz_get_str_256(rsaKeySize, serverKeyE, pubKey.e);
  
  rsa_public_key_clear(&pubKey);

  os->writeU32(serverKeyLength);
  os->writeBytes(serverKeyN, rsaKeySize);
  os->writeBytes(serverKeyE, rsaKeySize);
  os->flush();
}

bool SSecurityRSAAES::readPublicKey()
{
  rdr::InStream* is = sc->getInStream();
  if (!is->hasData(4))
    return false;
  is->setRestorePoint();
  clientKeyLength = is->readU32();
  if (clientKeyLength < MinKeyLength)
    throw std::runtime_error("Client key is too short");
  if (clientKeyLength > MaxKeyLength)
    throw std::runtime_error("Client key is too long");
  size_t size = (clientKeyLength + 7) / 8;
  if (!is->hasDataOrRestore(size * 2))
    return false;
  is->clearRestorePoint();
  clientKeyE = new uint8_t[size];
  clientKeyN = new uint8_t[size];
  is->readBytes(clientKeyN, size);
  is->readBytes(clientKeyE, size);
  rsa_public_key_init(&clientKey);
  nettle_mpz_set_str_256_u(clientKey.n, size, clientKeyN);
  nettle_mpz_set_str_256_u(clientKey.e, size, clientKeyE);
  if (!rsa_public_key_prepare(&clientKey))
    throw std::runtime_error("Client key is invalid");
  return true;
}

void SSecurityRSAAES::writeRandom()
{
  rdr::RandomStream rs;
  rdr::OutStream* os = sc->getOutStream();
  if (!rs.hasData(keySize / 8))
    throw std::runtime_error("Failed to generate random");
  rs.readBytes(serverRandom, keySize / 8);
  mpz_t x;
  mpz_init(x);
  int res;
  try {
    res = rsa_encrypt(&clientKey, &rs, random_func, keySize / 8,
                      serverRandom, x);
  } catch (...) {
    mpz_clear(x);
    throw;
  }
  if (!res) {
    mpz_clear(x);
    throw std::runtime_error("Failed to encrypt random");
  }
  uint8_t* buffer = new uint8_t[clientKey.size];
  nettle_mpz_get_str_256(clientKey.size, buffer, x);
  mpz_clear(x);
  os->writeU16(clientKey.size);
  os->writeBytes(buffer, clientKey.size);
  os->flush();
  delete[] buffer;
}

bool SSecurityRSAAES::readRandom()
{
  rdr::InStream* is = sc->getInStream();
  if (!is->hasData(2))
    return false;
  is->setRestorePoint();
  size_t size = is->readU16();
  if (size != serverKey.size)
    throw std::runtime_error("Server key length doesn't match");
  if (!is->hasDataOrRestore(size))
    return false;
  is->clearRestorePoint();
  uint8_t* buffer = new uint8_t[size];
  is->readBytes(buffer, size);
  size_t randomSize = keySize / 8;
  mpz_t x;
  nettle_mpz_init_set_str_256_u(x, size, buffer);
  delete[] buffer;
  if (!rsa_decrypt(&serverKey, &randomSize, clientRandom, x) ||
      randomSize != (size_t)keySize / 8) {
    mpz_clear(x);
    throw std::runtime_error("Failed to decrypt client random");
  }
  mpz_clear(x);
  return true;
}

void SSecurityRSAAES::setCipher()
{
  rawis = sc->getInStream();
  rawos = sc->getOutStream();
  uint8_t key[32];
  if (keySize == 128) {
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, 16, clientRandom);
    sha1_update(&ctx, 16, serverRandom);
    sha1_digest(&ctx, key);
    raos = new rdr::AESOutStream(rawos, key, 128);
    sha1_init(&ctx);
    sha1_update(&ctx, 16, serverRandom);
    sha1_update(&ctx, 16, clientRandom);
    sha1_digest(&ctx, key);
    rais = new rdr::AESInStream(rawis, key, 128);
  } else {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 32, clientRandom);
    sha256_update(&ctx, 32, serverRandom);
    sha256_digest(&ctx, key);
    raos = new rdr::AESOutStream(rawos, key, 256);
    sha256_init(&ctx);
    sha256_update(&ctx, 32, serverRandom);
    sha256_update(&ctx, 32, clientRandom);
    sha256_digest(&ctx, key);
    rais = new rdr::AESInStream(rawis, key, 256);
  }
  if (isAllEncrypted)
    sc->setStreams(rais, raos);
}

void SSecurityRSAAES::writeHash()
{
  uint8_t hash[32];
  size_t len = serverKeyLength;
  uint8_t lenServerKey[4] = {
    (uint8_t)((len & 0xff000000) >> 24),
    (uint8_t)((len & 0xff0000) >> 16),
    (uint8_t)((len & 0xff00) >> 8),
    (uint8_t)(len & 0xff)
  };
  len = clientKeyLength;
  uint8_t lenClientKey[4] = {
    (uint8_t)((len & 0xff000000) >> 24),
    (uint8_t)((len & 0xff0000) >> 16),
    (uint8_t)((len & 0xff00) >> 8),
    (uint8_t)(len & 0xff)
  };
  int hashSize;
  if (keySize == 128) {
    hashSize = 20;
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, 4, lenServerKey);
    sha1_update(&ctx, serverKey.size, serverKeyN);
    sha1_update(&ctx, serverKey.size, serverKeyE);
    sha1_update(&ctx, 4, lenClientKey);
    sha1_update(&ctx, clientKey.size, clientKeyN);
    sha1_update(&ctx, clientKey.size, clientKeyE);
    sha1_digest(&ctx, hash);
  } else {
    hashSize = 32;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 4, lenServerKey);
    sha256_update(&ctx, serverKey.size, serverKeyN);
    sha256_update(&ctx, serverKey.size, serverKeyE);
    sha256_update(&ctx, 4, lenClientKey);
    sha256_update(&ctx, clientKey.size, clientKeyN);
    sha256_update(&ctx, clientKey.size, clientKeyE);
    sha256_digest(&ctx, hash);
  }
  raos->writeBytes(hash, hashSize);
  raos->flush();
}

bool SSecurityRSAAES::readHash()
{
  uint8_t hash[32];
  uint8_t realHash[32];
  int hashSize = keySize == 128 ? 20 : 32;
  if (!rais->hasData(hashSize))
    return false;
  rais->readBytes(hash, hashSize);
  size_t len = serverKeyLength;
  uint8_t lenServerKey[4] = {
    (uint8_t)((len & 0xff000000) >> 24),
    (uint8_t)((len & 0xff0000) >> 16),
    (uint8_t)((len & 0xff00) >> 8),
    (uint8_t)(len & 0xff)
  };
  len = clientKeyLength;
  uint8_t lenClientKey[4] = {
    (uint8_t)((len & 0xff000000) >> 24),
    (uint8_t)((len & 0xff0000) >> 16),
    (uint8_t)((len & 0xff00) >> 8),
    (uint8_t)(len & 0xff)
  };
  if (keySize == 128) {
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, 4, lenClientKey);
    sha1_update(&ctx, clientKey.size, clientKeyN);
    sha1_update(&ctx, clientKey.size, clientKeyE);
    sha1_update(&ctx, 4, lenServerKey);
    sha1_update(&ctx, serverKey.size, serverKeyN);
    sha1_update(&ctx, serverKey.size, serverKeyE);
    sha1_digest(&ctx, realHash);
  } else {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 4, lenClientKey);
    sha256_update(&ctx, clientKey.size, clientKeyN);
    sha256_update(&ctx, clientKey.size, clientKeyE);
    sha256_update(&ctx, 4, lenServerKey);
    sha256_update(&ctx, serverKey.size, serverKeyN);
    sha256_update(&ctx, serverKey.size, serverKeyE);
    sha256_digest(&ctx, realHash);
  }
  if (memcmp(hash, realHash, hashSize) != 0)
    throw std::runtime_error("Hash doesn't match");
  return true;
}

void SSecurityRSAAES::clearSecrets()
{
  rsa_private_key_clear(&serverKey);
  rsa_public_key_clear(&clientKey);
  serverKey.size = 0;
  clientKey.size = 0;
  delete[] serverKeyN;
  delete[] serverKeyE;
  delete[] clientKeyN;
  delete[] clientKeyE;
  serverKeyN = nullptr;
  serverKeyE = nullptr;
  clientKeyN = nullptr;
  clientKeyE = nullptr;
  memset(serverRandom, 0, sizeof(serverRandom));
  memset(clientRandom, 0, sizeof(clientRandom));
}

void SSecurityRSAAES::writeSubtype()
{
  raos->writeU8(secType);
  raos->flush();
}

bool SSecurityRSAAES::readCredentials()
{
  if (!rais->hasData(1))
    return false;
  rais->setRestorePoint();
  uint8_t uLen = rais->readU8();
  if (!rais->hasDataOrRestore(uLen + 1))
    return false;
  if (uLen > 0) {
    char* buf = new char[uLen + 1];
    rais->readBytes((uint8_t*)buf, uLen);
    buf[uLen] = '\0';
    strncpy(this->username, buf, sizeof(this->username) - 1);
    this->username[sizeof(this->username) - 1] = '\0';
    delete[] buf;
  }
  uint8_t pLen = rais->readU8();
  if (!rais->hasDataOrRestore(pLen))
    return false;
  rais->clearRestorePoint();
  if (pLen > 0) {
    char* buf = new char[pLen + 1];
    rais->readBytes((uint8_t*)buf, pLen);
    buf[pLen] = '\0';
    strncpy(this->password, buf, sizeof(this->password) - 1);
    this->password[sizeof(this->password) - 1] = '\0';
    delete[] buf;
  }

  return true;
}

const char* SSecurityRSAAES::getUserName() const
{
  return username;
}

const char* SSecurityRSAAES::getPassword() const
{
  return password;
}
