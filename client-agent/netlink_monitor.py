#!/usr/bin/env python3

import os
import socket
import struct

XFRMNLGRP_EXPIRE = 0x2
XFRM_MSG_EXPIRE = 0x18


class NetlinkMonitor:

    def __init__(self, queue, verbose):
        self.queue = queue
        self.verbose = verbose
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_XFRM)
        self.s.bind((os.getpid(), XFRMNLGRP_EXPIRE))

    def monitor_msg_expire(self):
        """checks XFRMNLGRP_EXPIRE for XFRM_MSG_EXPIRE messages

        When new XFRM_MSG_EXPIRE messages arrive, the source address, destination address and spi
        are added to the queue as a tuple
        """
        while True:
            data = self.s.recv(65535)

            msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", data[:16])
            if msg_type != XFRM_MSG_EXPIRE:
                continue

            if self.verbose:
                print('[*] received XFRM_MSG_EXPIRE')

            # xfrm_address_t is 4 bytes (IPv4: only first byte used, IPv6: all bytes used)
            # sometimes 3 bytes unused space between entries of xfrm_usersa_info ?!

            # https://github.com/torvalds/linux/blob/master/include/uapi/linux/xfrm.h

            # struct xfrm_usersa_info {
            #   struct xfrm_selector		sel;
            #   struct xfrm_id			    id;
            #   xfrm_address_t			    saddr;
            #   struct xfrm_lifetime_cfg	lft;
            #   struct xfrm_lifetime_cur	curlft;
            #   struct xfrm_stats		    stats;
            #   __u32				        seq;
            #   __u32				        reqid;
            #   __u16				        family;
            #   __u8				        mode;		/* XFRM_MODE_xxx */
            #   __u8				        replay_window;
            #   __u8				        flags;
            # #define XFRM_STATE_NOECN	    1
            # #define XFRM_STATE_DECAP_DSCP	2
            # #define XFRM_STATE_NOPMTUDISC	4
            # #define XFRM_STATE_WILDRECV	8
            # #define XFRM_STATE_ICMP		16
            # #define XFRM_STATE_AF_UNSPEC	32
            # #define XFRM_STATE_ALIGN4	    64
            # #define XFRM_STATE_ESN		128
            # };

            # xfrm_selector should be empty -> ignoring
            # only xfrm_id and saddr are of importance

            # struct xfrm_id {
            #   xfrm_address_t	daddr;
            #   __be32		    spi;
            #   __u8		    proto;
            # };
            # bytes 72-93

            xfrm_id_spi, xfrm_id_proto = struct.unpack("=IB", data[88:93])
            daddr = str(socket.inet_ntoa(data[72:76]))
            spi = xfrm_id_spi.to_bytes(4, byteorder='little').hex()
            proto = str(xfrm_id_proto)
            if self.verbose:
                print('\tdaddr: ' + daddr)
                print('\tspi: ' + spi)
                print('\tproto: ' + proto)

            # xfrm_address_t    saddr;
            # bytes 96-112

            saddr = str(socket.inet_ntoa(data[96:100]))
            if self.verbose:
                print("\tsaddr: " + saddr)

            self.queue.put((saddr, daddr, spi))

