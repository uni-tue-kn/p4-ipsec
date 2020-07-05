/* Copyright 2013-present Barefoot Networks, Inc.
 * Modifications copyright 2018-present University of Tuebingen
 *   Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 * 
 * Modifications:
 * Marco Haeberle (marco.haeberle@uni-tuebingen.de)
 * Joshua Hartmann
 * Arwed Mett
 * Frederik Hauser (frederik.hauser@uni-tuebingen.de)
 *
 */

#include <openssl/aes.h>
//#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/extern.h>

//#include <bm/bm_sim/_assert.h>
//#include <unistd.h>

#include <condition_variable>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <deque>
#include <fstream>
#include <sstream>
#include <mutex>

#include "simple_switch.h"
#include "register_access.h"

namespace bm
{
class ExternCrypt : public ExternType
{
public:
  BM_EXTERN_ATTRIBUTES
  {
  }

  struct ctr_state
  {
    unsigned char ivec[16];
    unsigned int num;
    unsigned char ecount[16];
  };

  void init() override
  {
  }

  void init_ctr(struct ctr_state *state, const unsigned char iv[16])
  {
    state->num = 0;
    memset(state->ecount, 0, 16);
    memcpy(state->ivec, iv, 16);
  }

  void crypt_message(const unsigned char *src, unsigned char *dst,
                     unsigned long int src_len, const AES_KEY *key, const unsigned char *iv)
  {
    ctr_state state;
    init_ctr(&state, iv);
    AES_ctr128_encrypt(src, dst, src_len, key, state.ivec, state.ecount, &state.num);
  }

  void decrypt_aes_ctr(bm::Header &ipv4, bm::Header &esp, bm::Header &standard_metadata, const bm::Data &key_data, const bm::Data &key_hmac_data)
  {
    std::cout << "[IPSEC] processing packet\n";
    std::cout << "[IPSEC] Ingress port: " << this->get_packet().get_ingress_port() << "\n";
    std::cout << "[IPSEC] Egress port: " << this->get_packet().get_egress_port() << "\n";

    auto key_nonce = key_data.get_string();
    if (key_nonce.length() < 20)
    {
      //CLI schneidet führende Nullen ab, also fügen wir sie wieder hinzu
      key_nonce = std::string(20 - key_nonce.length(), '\0').append(key_nonce);
    }
    else if (key_nonce.length() > 20)
    {
      //sollte nicht vorkommen, da die CLI "zu lange" Parameter verhindert
      key_nonce.resize(20);
    }

    auto hmay_key = key_hmac_data.get_string();
    if (hmay_key.length() < 16)
    {
      //CLI schneidet führende Nullen ab, also fügen wir sie wieder hinzu
      hmay_key = std::string(16 - hmay_key.length(), '\0').append(hmay_key);
    }
    else if (hmay_key.length() > 16)
    {
      //sollte nicht vorkommen, da die CLI "zu lange" Parameter verhindert
      hmay_key.resize(16);
    }

    //the key consists of the key used for encryption and a nonce
    auto key_string = key_nonce.substr(0, 16);
    auto nonce_string = key_nonce.substr(16, 4);

    //prepare AES key
    std::vector<unsigned char> key_vect(key_string.begin(), key_string.end());
    AES_KEY key;
    AES_set_encrypt_key(key_vect.data(), 128, &key);

    std::vector<unsigned char> raw_packet_data;
    raw_packet_data.resize(get_packet().get_data_size(), '\0');
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size(),
              raw_packet_data.begin());

    std::cout << "[IPSEC] raw packet data length: " << raw_packet_data.size()
              << "\n";

    //check the ICV
    //ICV = 12 last octets of the ESP trailer
    std::vector<unsigned char> ICV;
    ICV.resize(12, '\0');
    std::copy(raw_packet_data.end() - 12, raw_packet_data.end(), ICV.begin());

    //concatenate ESP header, payload and ESP trailer
    std::vector<unsigned char> ICV_check;
    ICV_check.resize(raw_packet_data.size() - 12 + 8, '\0'); //-12: ICV, +8: ESP Header
    std::copy(esp[0].get_bytes().data(), esp[0].get_bytes().data() + 4,
              ICV_check.begin());
    std::copy(esp[1].get_bytes().data(), esp[1].get_bytes().data() + 4,
              ICV_check.begin() + 4);
    std::copy(raw_packet_data.begin(), raw_packet_data.end() - 12,
              ICV_check.begin() + 8);

    //compute HMAC
    std::vector<unsigned char> hmay_key_vect(hmay_key.begin(), hmay_key.end());
    unsigned char *hmac;
    unsigned int hmac_len;
    hmac = HMAC(EVP_md5(), hmay_key_vect.data(), hmay_key_vect.size(),
                ICV_check.data(), ICV_check.size(), NULL, &hmac_len);

    //drop packet if ICV and the computed hmac are not the same
    if (((hmac_len != 16) || std::memcmp(hmac, ICV.data(), ICV.size())) != 0)
    {
      standard_metadata
          .get_field(standard_metadata.get_header_type().get_field_offset("egress_spec"))
          .set("1FF");
      standard_metadata
          .get_field(standard_metadata.get_header_type().get_field_offset("mcast_grp"))
          .set("0");
    }

    //decryption
    //IV = first 16 Bytes of the payload
    std::vector<unsigned char> IV;
    IV.resize(8, '\0');
    std::copy(raw_packet_data.begin(), raw_packet_data.begin() + 8, IV.begin());

    //compose nonce, IV and blockcounter into the Counter Block Format (32bit, last bit 1, rest 0) (see RFC 3686)
    std::vector<unsigned char> IV_complete;
    IV_complete.resize(16, '\0');
    std::copy(nonce_string.begin(), nonce_string.end(), IV_complete.begin());
    std::copy(IV.begin(), IV.end(), IV_complete.begin() + 4);
    IV_complete[15] = (unsigned char)1; //block counter

    std::vector<unsigned char> encrypted;
    encrypted.resize(raw_packet_data.size() - 20, '\0');
    std::copy(raw_packet_data.begin() + 8, raw_packet_data.end() - 12,
              encrypted.begin());

    //AES_ctr128_encrypt seems not to work with char vectors -> use char array instead
    int encrypted_size = raw_packet_data.size() - 20;
    unsigned char decrypted_tmp[encrypted_size];
    memset(decrypted_tmp, 0, sizeof(decrypted_tmp));
    this->crypt_message((const unsigned char *)encrypted.data(),
                        (unsigned char *)decrypted_tmp,
                        (unsigned long int)raw_packet_data.size() - 20, &key,
                        IV_complete.data());
    std::vector<unsigned char> decrypted(decrypted_tmp,
                                         decrypted_tmp + encrypted_size);

    //next header
    //    char next_header = *(decrypted_tmp + encrypted_size - 1);

    //padding length
    char padding_length = *(decrypted_tmp + encrypted_size - 2);
    std::cout << "[IPSEC] padding length: " << padding_length << "\n";

    //payload
    std::vector<unsigned char> payload;
    payload.resize(encrypted_size - 2 - padding_length, '\0');
    std::copy(decrypted.begin(), decrypted.end() - 2 - padding_length,
              payload.begin());

    //prepare decrypted ipv4 header for transformation into p4 header fields
    std::vector<char> ipv4_new;
    ipv4_new.resize(20, '\0');
    std::copy(payload.begin(), payload.begin() + 20, ipv4_new.begin());

    //some header field's sizes are not a multiple of 1 byte, but bvm only supperts writing bytes to p4 header fields
    //-> bitwise magic necessary
    char version = (ipv4_new[0] >> 4) & 15;
    char ihl = ipv4_new[0] & 15;
    char flags = (ipv4_new[6] >> 5) & 7;
    std::vector<char> fragOffset;
    fragOffset.resize(2, '\0');
    fragOffset[0] = ((ipv4_new[6] & 31) << 3) | ((ipv4_new[7] >> 5) & 7);
    fragOffset[1] = ipv4_new[7] & 31;

    //write the content of the header fields into the p4 ipv4 header fields
    ipv4[0].set_bytes(&version, 1);       //version
    ipv4[1].set_bytes(&ihl, 1);           //ihl
    ipv4[2].set_bytes(&ipv4_new[1], 1);   //diffserv
    ipv4[3].set_bytes(&ipv4_new[2], 2);   //totalLen
    ipv4[4].set_bytes(&ipv4_new[4], 2);   //identification
    ipv4[5].set_bytes(&flags, 1);         //flags
    ipv4[6].set_bytes(&fragOffset[0], 2); //fragOffset
    ipv4[7].set_bytes(&ipv4_new[8], 1);   //ttl
    ipv4[8].set_bytes(&ipv4_new[9], 1);   //protocol
    ipv4[9].set_bytes(&ipv4_new[10], 2);  //hdrChecksum
    ipv4[10].set_bytes(&ipv4_new[12], 4); //srcAddr
    ipv4[11].set_bytes(&ipv4_new[16], 4); //dstAddr

    //replace payload
    //first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    //make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
        (unsigned long int)encrypted_size - 2 - padding_length - 20); //2 = padding length + next header, 20 = ipv4 header
    for (uint i = 0; i < (unsigned long int)encrypted_size - 2 - padding_length - 20; i++)
    {
      payload_start[i] = payload[i + 20]; //don't copy ipv4 header -> +20
    }
  }

  void encrypt_aes_ctr(bm::Header &ipv4, bm::Header &esp, const bm::Data &key_data, const bm::Data &key_hmac_data)
  {
    std::cout << "[IPSEC] processing packet\n";
    std::cout << "[IPSEC] read key and hmac\n";

    auto key_nonce = key_data.get_string();
    if (key_nonce.length() < 20)
    {
      //CLI schneidet führende Nullen ab, also fügen wir sie wieder hinzu
      key_nonce = std::string(20 - key_nonce.length(), '\0').append(key_nonce);
    }
    else if (key_nonce.length() > 20)
    {
      //sollte nicht vorkommen, da die CLI "zu lange" Parameter verhindert
      key_nonce.resize(20);
    }

    auto hmay_key = key_hmac_data.get_string();
    if (hmay_key.length() < 16)
    {
      //CLI schneidet führende Nullen ab, also fügen wir sie wieder hinzu
      hmay_key = std::string(16 - hmay_key.length(), '\0').append(hmay_key);
    }
    else if (hmay_key.length() > 16)
    {
      //sollte nicht vorkommen, da die CLI "zu lange" Parameter verhindert
      hmay_key.resize(16);
    }

    //the key consists of the key used for encryption and a nonce
    auto key_string = key_nonce.substr(0, 16);
    auto nonce_string = key_nonce.substr(16, 4);

    std::cout << "[IPSEC] prepare AES key\n";
    //prepare AES key
    std::vector<unsigned char> key_vect(key_string.begin(), key_string.end());
    AES_KEY key;
    AES_set_encrypt_key(key_vect.data(), 128, &key);

    std::cout << "[IPSEC] restore ipv4 header\n";
    //restore the ipv4 header that was stripped from the packet by p4
    //std::cout << get_packet() << std::endl;
    std::vector<unsigned char> raw_packet_data;
    auto raw_packet_size = get_packet().get_data_size() + 20;
    raw_packet_data.resize(raw_packet_size, '\0');

    std::vector<char> ipv4_reassemble_tmp;
    ipv4_reassemble_tmp.resize(3, '\0');
    std::copy(ipv4[0].get_bytes().data(), ipv4[0].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin());
    std::copy(ipv4[1].get_bytes().data(), ipv4[1].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin() + 1);

    ipv4_reassemble_tmp[0] = (ipv4_reassemble_tmp[0] << 4) | (ipv4_reassemble_tmp[1] & 15); //merge version and ihl into one byte

    std::copy(ipv4_reassemble_tmp.data(), ipv4_reassemble_tmp.data() + 1,
              raw_packet_data.begin()); //version + ihl
    std::copy(ipv4[2].get_bytes().data(), ipv4[2].get_bytes().data() + 1,
              raw_packet_data.begin() + 1); //diffserv
    std::copy(ipv4[3].get_bytes().data(), ipv4[3].get_bytes().data() + 2,
              raw_packet_data.begin() + 2); //totalLen
    std::copy(ipv4[4].get_bytes().data(), ipv4[4].get_bytes().data() + 2,
              raw_packet_data.begin() + 4); //identification

    std::copy(ipv4[5].get_bytes().data(), ipv4[5].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin());
    std::copy(ipv4[6].get_bytes().data(), ipv4[6].get_bytes().data() + 2,
              ipv4_reassemble_tmp.begin() + 1);
    ipv4_reassemble_tmp[0] = (ipv4_reassemble_tmp[0] << 5) | ((ipv4_reassemble_tmp[1] >> 3) & 31);
    ipv4_reassemble_tmp[1] = (ipv4_reassemble_tmp[1] << 5) | (ipv4_reassemble_tmp[2] >> 3 & 31);
    std::copy(ipv4_reassemble_tmp.data(), ipv4_reassemble_tmp.data() + 2,
              raw_packet_data.begin() + 6); //fragOffset + flags

    std::copy(ipv4[7].get_bytes().data(), ipv4[7].get_bytes().data() + 1,
              raw_packet_data.begin() + 8); //ttl
    std::copy(ipv4[8].get_bytes().data(), ipv4[8].get_bytes().data() + 1,
              raw_packet_data.begin() + 9); //protocol
    std::copy(ipv4[9].get_bytes().data(), ipv4[9].get_bytes().data() + 2,
              raw_packet_data.begin() + 10); //hdrChecksum
    std::copy(ipv4[10].get_bytes().data(), ipv4[10].get_bytes().data() + 4,
              raw_packet_data.begin() + 12); //srcAddr
    std::copy(ipv4[11].get_bytes().data(), ipv4[11].get_bytes().data() + 4,
              raw_packet_data.begin() + 16); //dstAddr

    std::cout << "[IPSEC] copy payload\n";
    //copy payload
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size(),
              raw_packet_data.begin() + 20);

    //check if we need to add padding
    char padding = 0;
    if (raw_packet_size % 16 != 0)
    {
      padding = 16 - (raw_packet_size % 16);
    }

    std::cout << "[IPSEC] add padding\n";
    raw_packet_size += padding + 2; //2: padding length and next header
    raw_packet_data.resize(raw_packet_size, '\0');

    //add padding length and next header
    raw_packet_data[raw_packet_size - 2] = padding;
    raw_packet_data[raw_packet_size - 1] = 4; //next header = ipv4

    std::cout << "[IPSEC] generate IV\n";
    //generate IV
    std::vector<unsigned char> IV;
    IV.resize(8, '\0');
    RAND_bytes(IV.data(), 8);

    //compose nonce, IV and blockcounter into the Counter Block Format (32bit, last bit 1, rest 0) (see RFC 3686)
    std::vector<unsigned char> IV_complete;
    IV_complete.resize(16, '\0');
    std::copy(nonce_string.begin(), nonce_string.end(), IV_complete.begin());
    std::copy(IV.begin(), IV.end(), IV_complete.begin() + 4);
    IV_complete[15] = (unsigned char)1; //block counter

    std::cout << "[IPSEC] encrypt\n";

    //encryption
    unsigned char encrypted[raw_packet_size];
    memset(encrypted, 0, sizeof(encrypted));
    crypt_message((const unsigned char *)raw_packet_data.data(),
                  (unsigned char *)encrypted, (unsigned long int)raw_packet_size, &key,
                  IV_complete.data());

    std::vector<unsigned char> payload;
    payload.resize(raw_packet_size + 8 + 12, '\0'); //8: IV, 12: ICV
    std::copy(IV.begin(), IV.end(), payload.begin());
    std::copy(encrypted, encrypted + raw_packet_size, payload.begin() + 8);

    std::cout << "[IPSEC] calculate IV\n";
    //calculate ICV
    std::vector<unsigned char> hmay_key_vect(hmay_key.begin(), hmay_key.end());
    std::vector<unsigned char> ICV_check;
    ICV_check.resize(payload.size() + 8 - 12, '\0'); //+8: ESP header, -12: ICV
    std::copy(esp[0].get_bytes().data(), esp[0].get_bytes().data() + 4,
              ICV_check.begin());
    std::copy(esp[1].get_bytes().data(), esp[1].get_bytes().data() + 4,
              ICV_check.begin() + 4);
    std::copy(payload.data(), payload.data() + payload.size() - 12,
              ICV_check.begin() + 8);
    unsigned int hmac_len;
    unsigned char *hmac = HMAC(EVP_md5(), hmay_key_vect.data(),
                               hmay_key_vect.size(), ICV_check.data(), ICV_check.size(), NULL,
                               &hmac_len);

    std::copy(hmac, hmac + 12, payload.end() - 12);

    std::cout << "[IPSEC] replace payload\n";
    //replace payload
    //first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    //make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
        (unsigned long int)payload.size());
    for (uint i = 0; i < payload.size(); i++)
    {
      payload_start[i] = payload[i]; //don't copy ipv4 header -> +20
    }

    std::cout << "[IPSEC] set esp.payload length meta data\n";
    //set esp payload length meta data
    std::vector<char> payload_length;
    payload_length.resize(2, '\0');
    payload_length[0] = (payload.size() >> 8) & 255;
    payload_length[1] = payload.size() & 255;

    std::cout << "[IPSEC] set header\n";
    auto &totalLen = ipv4.get_field(ipv4.get_header_type().get_field_offset("totalLen"));
    totalLen.set(payload.size() + 28);
    std::cout << "[IPSEC] finished\n";
  }

  void decrypt_null(bm::Header &ipv4, bm::Header &esp, bm::Header &standard_metadata)
  {
    std::cout << "[IPSEC] processing packet\n";
    std::cout << "[IPSEC] Ingress port: " << this->get_packet().get_ingress_port() << "\n";
    std::cout << "[IPSEC] Egress port: " << this->get_packet().get_egress_port() << "\n";

    std::vector<unsigned char> raw_packet_data;
    raw_packet_data.resize(get_packet().get_data_size(), '\0');
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size(),
              raw_packet_data.begin());

    std::cout << "[IPSEC] raw packet data length: " << raw_packet_data.size()
              << "\n";

    //prepare decrypted ipv4 header for transformation into p4 header fields
    std::vector<char> ipv4_new;
    ipv4_new.resize(20, '\0');
    std::copy(raw_packet_data.begin(), raw_packet_data.begin() + 20, ipv4_new.begin());

    //some header field's sizes are not a multiple of 1 byte, but bvm only supports writing bytes to p4 header fields
    //-> bitwise magic necessary
    char version = (ipv4_new[0] >> 4) & 15;
    char ihl = ipv4_new[0] & 15;
    char flags = (ipv4_new[6] >> 5) & 7;
    std::vector<char> fragOffset;
    fragOffset.resize(2, '\0');
    fragOffset[0] = ((ipv4_new[6] & 31) << 3) | ((ipv4_new[7] >> 5) & 7);
    fragOffset[1] = ipv4_new[7] & 31;

    //write the content of the header fields into the p4 ipv4 header fields
    ipv4[0].set_bytes(&version, 1);       //version
    ipv4[1].set_bytes(&ihl, 1);           //ihl
    ipv4[2].set_bytes(&ipv4_new[1], 1);   //diffserv
    ipv4[3].set_bytes(&ipv4_new[2], 2);   //totalLen
    ipv4[4].set_bytes(&ipv4_new[4], 2);   //identification
    ipv4[5].set_bytes(&flags, 1);         //flags
    ipv4[6].set_bytes(&fragOffset[0], 2); //fragOffset
    ipv4[7].set_bytes(&ipv4_new[8], 1);   //ttl
    ipv4[8].set_bytes(&ipv4_new[9], 1);   //protocol
    ipv4[9].set_bytes(&ipv4_new[10], 2);  //hdrChecksum
    ipv4[10].set_bytes(&ipv4_new[12], 4); //srcAddr
    ipv4[11].set_bytes(&ipv4_new[16], 4); //dstAddr

    //replace payload
    //first, get the length of the payload
    unsigned long int payload_size = get_packet().get_data_size() - 20 - 2; //2 = padding length + next header, 20 = ipv4 header
    std::cout << "[IPSEC] IPv4 payload length: " << payload_size << "\n";
    //then, remove all the data
    get_packet().remove(get_packet().get_data_size());
    //make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(payload_size);
    for (uint i = 0; i < payload_size; i++)
    {
      payload_start[i] = raw_packet_data[i + 20]; //don't copy ipv4 header -> +20
    }
  }

  void encrypt_null(bm::Header &ipv4, bm::Header &esp)
  {
    std::cout << "[IPSEC] processing packet\n";
    std::cout << "[IPSEC] read key and hmac\n";

    std::cout << "[IPSEC] restore ipv4 header\n";
    //restore the ipv4 header that was stripped from the packet by p4
    //std::cout << get_packet() << std::endl;
    std::vector<unsigned char> raw_packet_data;
    auto raw_packet_size = get_packet().get_data_size() + 20;
    raw_packet_data.resize(raw_packet_size, '\0');

    std::vector<char> ipv4_reassemble_tmp;
    ipv4_reassemble_tmp.resize(3, '\0');
    std::copy(ipv4[0].get_bytes().data(), ipv4[0].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin());
    std::copy(ipv4[1].get_bytes().data(), ipv4[1].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin() + 1);

    ipv4_reassemble_tmp[0] = (ipv4_reassemble_tmp[0] << 4) | (ipv4_reassemble_tmp[1] & 15); //merge version and ihl into one byte

    std::copy(ipv4_reassemble_tmp.data(), ipv4_reassemble_tmp.data() + 1,
              raw_packet_data.begin()); //version + ihl
    std::copy(ipv4[2].get_bytes().data(), ipv4[2].get_bytes().data() + 1,
              raw_packet_data.begin() + 1); //diffserv
    std::copy(ipv4[3].get_bytes().data(), ipv4[3].get_bytes().data() + 2,
              raw_packet_data.begin() + 2); //totalLen
    std::copy(ipv4[4].get_bytes().data(), ipv4[4].get_bytes().data() + 2,
              raw_packet_data.begin() + 4); //identification

    std::copy(ipv4[5].get_bytes().data(), ipv4[5].get_bytes().data() + 1,
              ipv4_reassemble_tmp.begin());
    std::copy(ipv4[6].get_bytes().data(), ipv4[6].get_bytes().data() + 2,
              ipv4_reassemble_tmp.begin() + 1);
    ipv4_reassemble_tmp[0] = (ipv4_reassemble_tmp[0] << 5) | ((ipv4_reassemble_tmp[1] >> 3) & 31);
    ipv4_reassemble_tmp[1] = (ipv4_reassemble_tmp[1] << 5) | (ipv4_reassemble_tmp[2] >> 3 & 31);
    std::copy(ipv4_reassemble_tmp.data(), ipv4_reassemble_tmp.data() + 2,
              raw_packet_data.begin() + 6); //fragOffset + flags

    std::copy(ipv4[7].get_bytes().data(), ipv4[7].get_bytes().data() + 1,
              raw_packet_data.begin() + 8); //ttl
    std::copy(ipv4[8].get_bytes().data(), ipv4[8].get_bytes().data() + 1,
              raw_packet_data.begin() + 9); //protocol
    std::copy(ipv4[9].get_bytes().data(), ipv4[9].get_bytes().data() + 2,
              raw_packet_data.begin() + 10); //hdrChecksum
    std::copy(ipv4[10].get_bytes().data(), ipv4[10].get_bytes().data() + 4,
              raw_packet_data.begin() + 12); //srcAddr
    std::copy(ipv4[11].get_bytes().data(), ipv4[11].get_bytes().data() + 4,
              raw_packet_data.begin() + 16); //dstAddr

    std::cout << "[IPSEC] copy payload\n";
    //copy payload
    std::copy(get_packet().data(),
              get_packet().data() + get_packet().get_data_size(),
              raw_packet_data.begin() + 20);

    //add padding length and next header field
    raw_packet_size += 2; //1 byte padding length and 2 byte next header
    raw_packet_data.resize(raw_packet_size, '\0');
    raw_packet_data[raw_packet_size - 2] = 0;
    raw_packet_data[raw_packet_size - 1] = 4; //next header = ipv4

    std::cout << "[IPSEC] replace payload\n";
    //replace payload
    //first, remove all the data
    get_packet().remove(get_packet().get_data_size());
    //make room for the ciphertext and write the ciphertext in it
    char *payload_start = get_packet().prepend(
        (unsigned long int)raw_packet_data.size());
    for (uint i = 0; i < raw_packet_data.size(); i++)
    {
      payload_start[i] = raw_packet_data[i]; //don't copy ipv4 header -> +20
    }

    std::cout << "[IPSEC] set header\n";
    auto &totalLen = ipv4.get_field(ipv4.get_header_type().get_field_offset("totalLen"));
    totalLen.set(raw_packet_data.size() + 28);
    std::cout << "[IPSEC] finished\n";
  }  

};

// do not put these inside an anonymous namespace or some compilers may complain
BM_REGISTER_EXTERN(ExternCrypt);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, decrypt_aes_ctr, Header &, Header &, Header &, const Data &, const Data &);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, encrypt_aes_ctr, Header &, Header &, const Data &, const Data &);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, decrypt_null, Header &, Header &, Header &);
BM_REGISTER_EXTERN_METHOD(ExternCrypt, encrypt_null, Header &, Header &);

BM_REGISTER_EXTERN_W_NAME(ipsec_crypt, ExternCrypt);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_crypt, ExternCrypt, decrypt_aes_ctr, Header &, Header &, Header &, const Data &, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_crypt, ExternCrypt, encrypt_aes_ctr, Header &, Header &, const Data &, const Data &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_crypt, ExternCrypt, decrypt_null, Header &, Header &, Header &);
BM_REGISTER_EXTERN_W_NAME_METHOD(ipsec_crypt, ExternCrypt, encrypt_null, Header &, Header &);

} // namespace bm

extern int import_primitives(SimpleSwitch *simple_switch);

packet_id_t SimpleSwitch::packet_id = 0;

class SimpleSwitch::MirroringSessions
{
public:
  bool add_session(mirror_id_t mirror_id,
                   const MirroringSessionConfig &config)
  {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID)
    {
      sessions_map[mirror_id] = config;
      return true;
    }
    else
    {
      bm::Logger::get()->error("mirror_id out of range. No session added.");
      return false;
    }
  }

  bool delete_session(mirror_id_t mirror_id)
  {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID)
    {
      return sessions_map.erase(mirror_id) == 1;
    }
    else
    {
      bm::Logger::get()->error("mirror_id out of range. No session deleted.");
      return false;
    }
  }

  bool get_session(mirror_id_t mirror_id,
                   MirroringSessionConfig *config) const
  {
    Lock lock(mutex);
    auto it = sessions_map.find(mirror_id);
    if (it == sessions_map.end())
      return false;
    *config = it->second;
    return true;
  }

private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable std::mutex mutex;
  std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal pakcets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class SimpleSwitch::InputBuffer
{
public:
  enum class PacketType
  {
    NORMAL,
    RESUBMIT,
    RECIRCULATE,
    SENTINEL // signal for the ingress thread to terminate
  };

  InputBuffer(size_t capacity_hi, size_t capacity_lo)
      : capacity_hi(capacity_hi), capacity_lo(capacity_lo) {}

  int push_front(PacketType packet_type, std::unique_ptr<Packet> &&item)
  {
    switch (packet_type)
    {
    case PacketType::NORMAL:
      return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo,
                        std::move(item), true);
    case PacketType::RESUBMIT:
    case PacketType::RECIRCULATE:
      return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                        std::move(item), false);
    case PacketType::SENTINEL:
      return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                        std::move(item), true);
    }
    _BM_UNREACHABLE("Unreachable statement");
    return 0;
  }

  void pop_back(std::unique_ptr<Packet> *pItem)
  {
    Lock lock(mutex);
    cvar_can_pop.wait(
        lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
    // give higher priority to resubmit/recirculate queue
    if (queue_hi.size() > 0)
    {
      *pItem = std::move(queue_hi.back());
      queue_hi.pop_back();
      lock.unlock();
      cvar_can_push_hi.notify_one();
    }
    else
    {
      *pItem = std::move(queue_lo.back());
      queue_lo.pop_back();
      lock.unlock();
      cvar_can_push_lo.notify_one();
    }
  }

private:
  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;
  using QueueImpl = std::deque<std::unique_ptr<Packet>>;

  int push_front(QueueImpl *queue, size_t capacity,
                 std::condition_variable *cvar,
                 std::unique_ptr<Packet> &&item, bool blocking)
  {
    Lock lock(mutex);
    while (queue->size() == capacity)
    {
      if (!blocking)
        return 0;
      cvar->wait(lock);
    }
    queue->push_front(std::move(item));
    lock.unlock();
    cvar_can_pop.notify_one();
    return 1;
  }

  mutable std::mutex mutex;
  mutable std::condition_variable cvar_can_push_hi;
  mutable std::condition_variable cvar_can_push_lo;
  mutable std::condition_variable cvar_can_pop;
  size_t capacity_hi;
  size_t capacity_lo;
  QueueImpl queue_hi;
  QueueImpl queue_lo;
};

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port)
    : Switch(enable_swap),
      drop_port(drop_port),
      input_buffer(new InputBuffer(
          1024 /* normal capacity */, 1024 /* resubmit/recirc capacity */)),
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
      egress_buffers(nb_egress_threads,
                     64, EgressThreadMapper(nb_egress_threads),
                     SSWITCH_PRIORITY_QUEUEING_NB_QUEUES),
#else
      egress_buffers(nb_egress_threads,
                     64, EgressThreadMapper(nb_egress_threads)),
#endif
      output_buffer(128),
      // cannot use std::bind because of a clang bug
      // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
      my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                            const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
      }),
      pre(new McSimplePreLAG()),
      start(clock::now()),
      mirroring_sessions(new MirroringSessions())
{
  add_component<McSimplePreLAG>(pre);

  add_required_field("standard_metadata", "ingress_port");
  add_required_field("standard_metadata", "packet_length");
  add_required_field("standard_metadata", "instance_type");
  add_required_field("standard_metadata", "egress_spec");
  add_required_field("standard_metadata", "egress_port");

  force_arith_header("standard_metadata");
  force_arith_header("queueing_metadata");
  force_arith_header("intrinsic_metadata");

  import_primitives(this);
}

int SimpleSwitch::receive_(port_t port_num, const char *buffer, int len)
{
  // this is a good place to call this, because blocking this thread will not
  // block the processing of existing packet instances, which is a requirement
  if (do_swap() == 0)
  {
    check_queueing_metadata();
  }

  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();
  RegisterAccess::clear_all(packet.get());

  // setting standard metadata

  phv->get_field("standard_metadata.ingress_port").set(port_num);
  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
  phv->get_field("standard_metadata.packet_length").set(len);
  Field &f_instance_type = phv->get_field("standard_metadata.instance_type");
  f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

  if (phv->has_field("intrinsic_metadata.ingress_global_timestamp"))
  {
    phv->get_field("intrinsic_metadata.ingress_global_timestamp")
        .set(get_ts().count());
  }

  input_buffer->push_front(
      InputBuffer::PacketType::NORMAL, std::move(packet));
  return 0;
}

void SimpleSwitch::start_and_return_()
{
  check_queueing_metadata();

  threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
  for (size_t i = 0; i < nb_egress_threads; i++)
  {
    threads_.push_back(std::thread(&SimpleSwitch::egress_thread, this, i));
  }
  threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
}

SimpleSwitch::~SimpleSwitch()
{
  input_buffer->push_front(
      InputBuffer::PacketType::SENTINEL, nullptr);
  for (size_t i = 0; i < nb_egress_threads; i++)
  {
    // The push_front call is called inside a while loop because there is no
    // guarantee that the sentinel was enqueued otherwise. It should not be an
    // issue because at this stage the ingress thread has been sent a signal to
    // stop, and only egress clones can be sent to the buffer.
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    while (egress_buffers.push_front(i, 0, nullptr) == 0)
      continue;
#else
    while (egress_buffers.push_front(i, nullptr) == 0)
      continue;
#endif
  }
  output_buffer.push_front(nullptr);
  for (auto &thread_ : threads_)
  {
    thread_.join();
  }
}

void SimpleSwitch::reset_target_state_()
{
  bm::Logger::get()->debug("Resetting simple_switch target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

bool SimpleSwitch::mirroring_add_session(mirror_id_t mirror_id,
                                         const MirroringSessionConfig &config)
{
  return mirroring_sessions->add_session(mirror_id, config);
}

bool SimpleSwitch::mirroring_delete_session(mirror_id_t mirror_id)
{
  return mirroring_sessions->delete_session(mirror_id);
}

bool SimpleSwitch::mirroring_get_session(mirror_id_t mirror_id,
                                         MirroringSessionConfig *config) const
{
  return mirroring_sessions->get_session(mirror_id, config);
}

int SimpleSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts)
{
  egress_buffers.set_capacity(port, depth_pkts);
  return 0;
}

int SimpleSwitch::set_all_egress_queue_depths(const size_t depth_pkts)
{
  egress_buffers.set_capacity_for_all(depth_pkts);
  return 0;
}

int SimpleSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps)
{
  egress_buffers.set_rate(port, rate_pps);
  return 0;
}

int SimpleSwitch::set_all_egress_queue_rates(const uint64_t rate_pps)
{
  egress_buffers.set_rate_for_all(rate_pps);
  return 0;
}

uint64_t
SimpleSwitch::get_time_elapsed_us() const
{
  return get_ts().count();
}

uint64_t
SimpleSwitch::get_time_since_epoch_us() const
{
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void SimpleSwitch::set_transmit_fn(TransmitFn fn)
{
  my_transmit_fn = std::move(fn);
}

void SimpleSwitch::transmit_thread()
{
  while (1)
  {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);
    if (packet == nullptr)
      break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());
    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

ts_res
SimpleSwitch::get_ts() const
{
  return duration_cast<ts_res>(clock::now() - start);
}

void SimpleSwitch::enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet)
{
  packet->set_egress_port(egress_port);

  PHV *phv = packet->get_phv();

  if (with_queueing_metadata)
  {
    phv->get_field("queueing_metadata.enq_timestamp").set(get_ts().count());
    phv->get_field("queueing_metadata.enq_qdepth")
        .set(egress_buffers.size(egress_port));
  }

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
  size_t priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ? phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
  if (priority >= SSWITCH_PRIORITY_QUEUEING_NB_QUEUES)
  {
    bm::Logger::get()->error("Priority out of range, dropping packet");
    return;
  }
  egress_buffers.push_front(
      egress_port, SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority,
      std::move(packet));
#else
  egress_buffers.push_front(egress_port, std::move(packet));
#endif
}

// used for ingress cloning, resubmit
void SimpleSwitch::copy_field_list_and_set_type(
    const std::unique_ptr<Packet> &packet,
    const std::unique_ptr<Packet> &packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id)
{
  PHV *phv_copy = packet_copy->get_phv();
  phv_copy->reset_metadata();
  FieldList *field_list = this->get_field_list(field_list_id);
  field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
  phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void SimpleSwitch::check_queueing_metadata()
{
  // TODO(antonin): add qid in required fields
  bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
  bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
  bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
  bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
  if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e)
  {
    if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e)
      with_queueing_metadata = true;
    else
      bm::Logger::get()->warn(
          "Your JSON input defines some but not all queueing metadata fields");
  }
}

void SimpleSwitch::multicast(Packet *packet, unsigned int mgid)
{
  auto *phv = packet->get_phv();
  auto &f_rid = phv->get_field("intrinsic_metadata.egress_rid");
  const auto pre_out = pre->replicate({mgid});
  auto packet_size =
      packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
  for (const auto &out : pre_out)
  {
    auto egress_port = out.egress_port;
    BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
    f_rid.set(out.rid);
    std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
    RegisterAccess::clear_all(packet_copy.get());
    packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                              packet_size);
    enqueue(egress_port, std::move(packet_copy));
  }
}

void SimpleSwitch::ingress_thread()
{
  PHV *phv;

  while (1)
  {
    std::unique_ptr<Packet> packet;
    input_buffer->pop_back(&packet);
    if (packet == nullptr)
      break;

    // TODO(antonin): only update these if swapping actually happened?
    Parser *parser = this->get_parser("parser");
    Pipeline *ingress_mau = this->get_pipeline("ingress");

    phv = packet->get_phv();

    port_t ingress_port = packet->get_ingress_port();
    (void)ingress_port;
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                    ingress_port);

    auto ingress_packet_size =
        packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    /* This looks like it comes out of the blue. However this is needed for
       ingress cloning. The parser updates the buffer state (pops the parsed
       headers) to make the deparser's job easier (the same buffer is
       re-used). But for ingress cloning, the original packet is needed. This
       kind of looks hacky though. Maybe a better solution would be to have the
       parser leave the buffer unchanged, and move the pop logic to the
       deparser. TODO? */
    const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();
    parser->parse(packet.get());

    if (phv->has_field("standard_metadata.parser_error"))
    {
      phv->get_field("standard_metadata.parser_error").set(packet->get_error_code().get());
    }

    if (phv->has_field("standard_metadata.checksum_error"))
    {
      phv->get_field("standard_metadata.checksum_error").set(packet->get_checksum_error() ? 1 : 0);
    }

    ingress_mau->apply(packet.get());

    packet->reset_exit();

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    port_t egress_spec = f_egress_spec.get_uint();

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    int learn_id = RegisterAccess::get_lf_field_list(packet.get());
    unsigned int mgid = 0u;

    // detect mcast support, if this is true we assume that other fields needed
    // for mcast are also defined
    if (phv->has_field("intrinsic_metadata.mcast_grp"))
    {
      Field &f_mgid = phv->get_field("intrinsic_metadata.mcast_grp");
      mgid = f_mgid.get_uint();
    }

    // INGRESS CLONING
    if (clone_mirror_session_id)
    {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured)
      {
        const Packet::buffer_state_t packet_out_state =
            packet->save_buffer_state();
        packet->restore_buffer_state(packet_in_state);
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                  ingress_packet_size);
        // we need to parse again
        // the alternative would be to pay the (huge) price of PHV copy for
        // every ingress packet
        parser->parse(packet_copy.get());
        copy_field_list_and_set_type(packet, packet_copy,
                                     PKT_INSTANCE_TYPE_INGRESS_CLONE,
                                     field_list_id);
        if (config.mgid_valid)
        {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid)
        {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          enqueue(config.egress_port, std::move(packet_copy));
        }
        packet->restore_buffer_state(packet_out_state);
      }
    }

    // LEARNING
    if (learn_id > 0)
    {
      get_learn_engine()->learn(learn_id, *packet.get());
    }

    // RESUBMIT
    auto resubmit_flag = RegisterAccess::get_resubmit_flag(packet.get());
    if (resubmit_flag)
    {
      BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");
      // get the packet ready for being parsed again at the beginning of
      // ingress
      packet->restore_buffer_state(packet_in_state);
      p4object_id_t field_list_id = resubmit_flag;
      RegisterAccess::set_resubmit_flag(packet.get(), 0);
      // TODO(antonin): a copy is not needed here, but I don't yet have an
      // optimized way of doing this
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      copy_field_list_and_set_type(packet, packet_copy,
                                   PKT_INSTANCE_TYPE_RESUBMIT,
                                   field_list_id);
      RegisterAccess::clear_all(packet_copy.get());
      input_buffer->push_front(
          InputBuffer::PacketType::RESUBMIT, std::move(packet_copy));
      continue;
    }

    // MULTICAST
    if (mgid != 0)
    {
      BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet");
      auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
      f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
      multicast(packet.get(), mgid);
      // when doing multicast, we discard the original packet
      continue;
    }

    port_t egress_port = egress_spec;
    BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

    if (egress_port == drop_port)
    { // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      continue;
    }
    auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    enqueue(egress_port, std::move(packet));
  }
}

void SimpleSwitch::egress_thread(size_t worker_id)
{
  PHV *phv;

  while (1)
  {
    std::unique_ptr<Packet> packet;
    size_t port;
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    size_t priority;
    egress_buffers.pop_back(worker_id, &port, &priority, &packet);
#else
    egress_buffers.pop_back(worker_id, &port, &packet);
#endif
    if (packet == nullptr)
      break;

    Deparser *deparser = this->get_deparser("deparser");
    Pipeline *egress_mau = this->get_pipeline("egress");

    phv = packet->get_phv();

    if (phv->has_field("intrinsic_metadata.egress_global_timestamp"))
    {
      phv->get_field("intrinsic_metadata.egress_global_timestamp")
          .set(get_ts().count());
    }

    if (with_queueing_metadata)
    {
      auto enq_timestamp =
          phv->get_field("queueing_metadata.enq_timestamp").get<ts_res::rep>();
      phv->get_field("queueing_metadata.deq_timedelta").set(get_ts().count() - enq_timestamp);
      phv->get_field("queueing_metadata.deq_qdepth").set(egress_buffers.size(port));
      if (phv->has_field("queueing_metadata.qid"))
      {
        auto &qid_f = phv->get_field("queueing_metadata.qid");
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
        qid_f.set(SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority);
#else
        qid_f.set(0);
#endif
      }
    }

    phv->get_field("standard_metadata.egress_port").set(port);

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    f_egress_spec.set(0);

    phv->get_field("standard_metadata.packet_length").set(packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    egress_mau->apply(packet.get());

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    // EGRESS CLONING
    if (clone_mirror_session_id)
    {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at egress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured)
      {
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy =
            packet->clone_with_phv_reset_metadata_ptr();
        PHV *phv_copy = packet_copy->get_phv();
        FieldList *field_list = this->get_field_list(field_list_id);
        field_list->copy_fields_between_phvs(phv_copy, phv);
        phv_copy->get_field("standard_metadata.instance_type")
            .set(PKT_INSTANCE_TYPE_EGRESS_CLONE);
        if (config.mgid_valid)
        {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid)
        {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          RegisterAccess::clear_all(packet_copy.get());
          enqueue(config.egress_port, std::move(packet_copy));
        }
      }
    }

    // TODO(antonin): should not be done like this in egress pipeline
    port_t egress_spec = f_egress_spec.get_uint();
    if (egress_spec == drop_port)
    { // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
      continue;
    }

    deparser->deparse(packet.get());

    // RECIRCULATE
    auto recirculate_flag = RegisterAccess::get_recirculate_flag(packet.get());
    if (recirculate_flag)
    {
      BMLOG_DEBUG_PKT(*packet, "Recirculating packet");
      p4object_id_t field_list_id = recirculate_flag;
      RegisterAccess::set_recirculate_flag(packet.get(), 0);
      FieldList *field_list = this->get_field_list(field_list_id);
      // TODO(antonin): just like for resubmit, there is no need for a copy
      // here, but it is more convenient for this first prototype
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      PHV *phv_copy = packet_copy->get_phv();
      phv_copy->reset_metadata();
      field_list->copy_fields_between_phvs(phv_copy, phv);
      phv_copy->get_field("standard_metadata.instance_type")
          .set(PKT_INSTANCE_TYPE_RECIRC);
      size_t packet_size = packet_copy->get_data_size();
      RegisterAccess::clear_all(packet_copy.get());
      packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                packet_size);
      phv_copy->get_field("standard_metadata.packet_length").set(packet_size);
      // TODO(antonin): really it may be better to create a new packet here or
      // to fold this functionality into the Packet class?
      packet_copy->set_ingress_length(packet_size);
      input_buffer->push_front(
          InputBuffer::PacketType::RECIRCULATE, std::move(packet_copy));
      continue;
    }

    output_buffer.push_front(std::move(packet));
  }
}
