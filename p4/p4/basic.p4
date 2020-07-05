/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CONTROLLER_PORT 16

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTOCOL_ESP = 0x32;

const bit<16> IPSEC_SOFT_PACKET_LIMIT = 1;
const bit<16> IPSEC_HARD_PACKET_LIMIT = 2;

const bit<16> IPSEC_RESET_COUNTER = 60001;

/* Headers */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header cpu_header_t {
    bit<64> zeros;
    bit<16> reason;
    bit<16> port;
    bit<48> timestamp;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header esp_t {
	bit<32> spi;
	bit<32> sequenceNumber;
}

/* Metadata from the architecture */
struct intrinsic_metadata_t {
	bit<48> ingress_global_timestamp;
}

/* User-defined metadata */
struct user_metadata_t {
	bit<4> spd_mark;
    bool bypass;
}

struct esp_metadata_t {
	bit<16> payloadLength;
}

struct metadata {
	@metadata @name("intrinsic_metadata")
	intrinsic_metadata_t 	intrinsic_metadata;
    user_metadata_t	  		user_metadata;
	esp_metadata_t 			esp_meta;
}

struct headers {
    cpu_header_t cpu_header;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    esp_t         esp;
}

/* Parser */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
			PROTOCOL_ESP: parse_esp;
			default: accept;
		}
    }

    state parse_esp {
		packet.extract(hdr.esp);
		transition accept;
	}

}

/* Checksum Verification */

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/* Ingress Processing */

extern ipsec_crypt {
	ipsec_crypt();
	void decrypt_aes_ctr(inout ipv4_t ipv4, inout esp_t esp, inout standard_metadata_t standard_metadata, in bit<160> key, in bit<128> key_hmac);
	void encrypt_aes_ctr(inout ipv4_t ipv4, inout esp_t esp, in bit<160> key, in bit<128> key_hmac);
    void encrypt_null(inout ipv4_t ipv4, inout esp_t esp);
    void decrypt_null(inout ipv4_t ipv4, inout esp_t esp, inout standard_metadata_t standard_metadata);
}

ipsec_crypt() ipsecCrypt;  // instantiation

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1024) counters;
	bool notify_soft = false;
	bool notify_hard = false;
	bool do_drop = false;
	bit<32> current_register = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_controller(bit<16> reason){
		standard_metadata.egress_spec = CONTROLLER_PORT;
        hdr.cpu_header.setValid();
        hdr.cpu_header.reason = reason;
        hdr.cpu_header.timestamp = standard_metadata.ingress_global_timestamp;
	}
    
    action l2_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action l3_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action esp_decrypt_aes_ctr(bit<160> key, bit<128> key_hmac, bit<32> register_index) {
		ipsecCrypt.decrypt_aes_ctr(hdr.ipv4, hdr.esp, standard_metadata, key, key_hmac);
		hdr.esp.setInvalid();
		bit<32> tmp;
		counters.read(tmp, register_index);
		counters.write(register_index, tmp + 1);
	}

    action esp_decrypt_null(bit<32> register_index) {
		ipsecCrypt.decrypt_null(hdr.ipv4, hdr.esp, standard_metadata);
		hdr.esp.setInvalid();
		bit<32> tmp;
		counters.read(tmp, register_index);
		counters.write(register_index, tmp + 1);
	}

    action esp_encrypt_aes_ctr(bit<160> key, bit<128> key_hmac, bit<32> spi, ip4Addr_t src, ip4Addr_t dst, 
                        bit<32> register_index, bit<32> soft_packet_limit, bit<32> hard_packet_limit) {

		bit<32> tmp;
		counters.read(tmp, register_index);

		hdr.esp.setValid();
		hdr.esp.spi = spi;
		hdr.esp.sequenceNumber = tmp + 1;
		ipsecCrypt.encrypt_aes_ctr(hdr.ipv4, hdr.esp, key, key_hmac); //encrypts and sets ipv4 header length
		hdr.ipv4.identification = 1;
		hdr.ipv4.flags = 2;
		hdr.ipv4.fragOffset = 0;
		hdr.ipv4.ttl = 64;
		hdr.ipv4.protocol = PROTOCOL_ESP;
		hdr.ipv4.srcAddr = src;
		hdr.ipv4.dstAddr = dst;

		counters.write(register_index, tmp + 1);

		notify_soft = soft_packet_limit == tmp;
		notify_hard = hard_packet_limit == tmp;
		do_drop = tmp > hard_packet_limit;
		current_register = register_index;
	}

    action esp_encrypt_null(bit<32> spi, ip4Addr_t src, ip4Addr_t dst, 
                        bit<32> register_index, bit<32> soft_packet_limit, bit<32> hard_packet_limit) {

		bit<32> tmp;
		counters.read(tmp, register_index);

		hdr.esp.setValid();
		hdr.esp.spi = spi;
		hdr.esp.sequenceNumber = tmp + 1;
		ipsecCrypt.encrypt_null(hdr.ipv4, hdr.esp);
		hdr.ipv4.identification = 1;
		hdr.ipv4.flags = 2;
		hdr.ipv4.fragOffset = 0;
		hdr.ipv4.ttl = 64;
		hdr.ipv4.protocol = PROTOCOL_ESP;
		hdr.ipv4.srcAddr = src;
		hdr.ipv4.dstAddr = dst;

		counters.write(register_index, tmp + 1);

		notify_soft = soft_packet_limit == tmp;
		notify_hard = hard_packet_limit == tmp;
		do_drop = tmp > hard_packet_limit;
		current_register = register_index;
	}

    action add_spd_mark(bit<4> spd_mark){
        meta.user_metadata.spd_mark = spd_mark;
    }

    action clone_packet() {
        const bit<32> REPORT_MIRROR_SESSION_ID = 500;
        // Clone from ingress to egress pipeline
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }

    action sadb_acquire(){
		standard_metadata.egress_spec = CONTROLLER_PORT;
        hdr.cpu_header.setValid();
        hdr.cpu_header.reason = 3;
        hdr.cpu_header.timestamp = standard_metadata.ingress_global_timestamp;
	}
    
	table sad_encrypt {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			esp_encrypt_aes_ctr;
            esp_encrypt_null;
            sadb_acquire;
		}
		size = 1024;
		default_action = sadb_acquire;
	}

    table sad_decrypt {
		key = {
			hdr.ipv4.srcAddr: exact;
			hdr.ipv4.dstAddr: exact;
			hdr.esp.spi:	  exact;
		}
		actions = {
			NoAction;
			esp_decrypt_aes_ctr;
            esp_decrypt_null;
		}
		size = 1024;
		default_action = NoAction;
	}

    table forward {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            l3_forward;
            l2_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table spd {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            add_spd_mark;
            drop();
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        
        if (hdr.esp.isValid()) {
			sad_decrypt.apply();
            forward.apply();
		} else if(hdr.ipv4.isValid()) {

            /* Apply SPD */
            spd.apply();
            
            /* Process Result of SPD matching */
            if(meta.user_metadata.spd_mark == 1){
                /* BYPASS */
                forward.apply();
            } else if (meta.user_metadata.spd_mark == 2){
                /* PROTECT */
                sad_encrypt.apply();
                forward.apply();
            }
        }

        if(do_drop) {
			mark_to_drop(standard_metadata);
			exit;
		} else if(notify_soft) {
            send_to_controller(IPSEC_SOFT_PACKET_LIMIT);
            exit;
		} else if(notify_hard) {
			send_to_controller(IPSEC_HARD_PACKET_LIMIT);
			exit;
		}
    }
}

/* Egress Processing */

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/* Checksum Computation */

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/* Deparser */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.cpu_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.esp);
    }
}

/* Switch */

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
