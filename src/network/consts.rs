#![allow(dead_code)]
use nix::{request_code_read, request_code_write};
use std::ffi::{c_int, c_uint};
use std::mem::size_of;

/* Ioctl defines */
pub const TUNSETNOCSUM: u64 = request_code_write!('T', 200, size_of::<c_int>());
pub const TUNSETDEBUG: u64 = request_code_write!('T', 201, size_of::<c_int>());
pub const TUNSETIFF: u64 = request_code_write!('T', 202, size_of::<c_int>());
pub const TUNSETPERSIST: u64 = request_code_write!('T', 203, size_of::<c_int>());
pub const TUNSETOWNER: u64 = request_code_write!('T', 204, size_of::<c_int>());
pub const TUNSETLINK: u64 = request_code_write!('T', 205, size_of::<c_int>());
pub const TUNSETGROUP: u64 = request_code_write!('T', 206, size_of::<c_int>());
pub const TUNGETFEATURES: u64 = request_code_read!('T', 207, size_of::<c_uint>());
pub const TUNSETOFFLOAD: u64 = request_code_write!('T', 208, size_of::<c_uint>());
pub const TUNSETTXFILTER: u64 = request_code_write!('T', 209, size_of::<c_uint>());
pub const TUNGETIFF: u64 = request_code_read!('T', 210, size_of::<c_uint>());
pub const TUNGETSNDBUF: u64 = request_code_read!('T', 211, size_of::<c_int>());
pub const TUNSETSNDBUF: u64 = request_code_write!('T', 212, size_of::<c_int>());
// pub const TUNATTACHFILTER: u64 = request_code_write!('T', 213, struct sock_fprog);
// pub const TUNDETACHFILTER: u64 = request_code_write!('T', 214, struct sock_fprog);
pub const TUNGETVNETHDRSZ: u64 = request_code_read!('T', 215, size_of::<c_int>());
pub const TUNSETVNETHDRSZ: u64 = request_code_write!('T', 216, size_of::<c_int>());
pub const TUNSETQUEUE: u64 = request_code_write!('T', 217, size_of::<c_int>());
pub const TUNSETIFINDEX: u64 = request_code_write!('T', 218, size_of::<c_uint>());
// pub const TUNGETFILTER: u64 = request_code_read!('T', 219, struct sock_fprog);
pub const TUNSETVNETLE: u64 = request_code_write!('T', 220, size_of::<c_int>());
pub const TUNGETVNETLE: u64 = request_code_read!('T', 221, size_of::<c_int>());
/* The TUNSETVNETBE and TUNGETVNETBE ioctls are for cross-endian support on
 * little-endian hosts. Not all kernel configurations support them, but all
 * configurations that support SET also support GET.
 */
// pub const TUNSETVNETBE request_code_write!('T', 222, int)
// pub const TUNGETVNETBE request_code_read!('T', 223, int)
// pub const TUNSETSTEERINGEBPF request_code_read!('T', 224, int)
// pub const TUNSETFILTEREBPF request_code_read!('T', 225, int)
// pub const TUNSETCARRIER request_code_write!('T', 226, int)
// pub const TUNGETDEVNETNS _IO('T', 227)

/* TUNSETIFF ifr flags */
pub const IFF_TUN: u16 = 0x0001;
pub const IFF_TAP: u16 = 0x0002;
pub const IFF_NAPI: u16 = 0x0010;
pub const IFF_NAPI_FRAGS: u16 = 0x0020;

/* Used in TUNSETIFF to bring up tun/tap without carrier */
pub const IFF_NO_CARRIER: u16 = 0x0040;
pub const IFF_NO_PI: u16 = 0x1000;

/* This flag has no real effect */
pub const IFF_ONE_QUEUE: u16 = 0x2000;
pub const IFF_VNET_HDR: u16 = 0x4000;
pub const IFF_TUN_EXCL: u16 = 0x8000;
pub const IFF_MULTI_QUEUE: u16 = 0x0100;
pub const IFF_ATTACH_QUEUE: u16 = 0x0200;
pub const IFF_DETACH_QUEUE: u16 = 0x0400;

/* read-only flag */
pub const IFF_PERSIST: u16 = 0x0800;
pub const IFF_NOFILTER: u16 = 0x1000;

/* Socket options */
pub const TUN_TX_TIMESTAMP: u16 = 1;

/* Features for GSO (TUNSETOFFLOAD). */
pub const TUN_F_CSUM: u16 = 0x01; /* You can hand me unchecksummed packets. */
pub const TUN_F_TSO4: u16 = 0x02; /* I can handle TSO for IPv4 packets */
pub const TUN_F_TSO6: u16 = 0x04; /* I can handle TSO for IPv6 packets */
pub const TUN_F_TSO_ECN: u16 = 0x08; /* I can handle TSO with ECN bits. */
pub const TUN_F_UFO: u16 = 0x10; /* I can handle UFO packets */
pub const TUN_F_USO4: u16 = 0x20; /* I can handle USO for IPv4 packets */
pub const TUN_F_USO6: u16 = 0x40; /* I can handle USO for IPv6 packets */

/* Routing table calls. */
pub const SIOCADDRT: u64 = 0x890B; /* add routing table entry */
pub const SIOCDELRT: u64 = 0x890C; /* delete routing table entry */
pub const SIOCRTMSG: u64 = 0x890D; /* call to routing system */

/* Socket configuration controls. */
pub const SIOCGIFNAME: u64 = 0x8910; /* get iface name */
pub const SIOCSIFLINK: u64 = 0x8911; /* set iface channel */
pub const SIOCGIFCONF: u64 = 0x8912; /* get iface list */
pub const SIOCGIFFLAGS: u64 = 0x8913; /* get flags */
pub const SIOCSIFFLAGS: u64 = 0x8914; /* set flags */
pub const SIOCGIFADDR: u64 = 0x8915; /* get PA address */
pub const SIOCSIFADDR: u64 = 0x8916; /* set PA address */
pub const SIOCGIFDSTADDR: u64 = 0x8917; /* get remote PA address */
pub const SIOCSIFDSTADDR: u64 = 0x8918; /* set remote PA address */
pub const SIOCGIFBRDADDR: u64 = 0x8919; /* get broadcast PA address */
pub const SIOCSIFBRDADDR: u64 = 0x891a; /* set broadcast PA address */
pub const SIOCGIFNETMASK: u64 = 0x891b; /* get network PA mask */
pub const SIOCSIFNETMASK: u64 = 0x891c; /* set network PA mask */
pub const SIOCGIFMETRIC: u64 = 0x891d; /* get metric */
pub const SIOCSIFMETRIC: u64 = 0x891e; /* set metric */
pub const SIOCGIFMEM: u64 = 0x891f; /* get memory address (BSD) */
pub const SIOCSIFMEM: u64 = 0x8920; /* set memory address (BSD) */
pub const SIOCGIFMTU: u64 = 0x8921; /* get MTU size */
pub const SIOCSIFMTU: u64 = 0x8922; /* set MTU size */
pub const SIOCSIFNAME: u64 = 0x8923; /* set interface name */
pub const SIOCSIFHWADDR: u64 = 0x8924; /* set hardware address */
pub const SIOCGIFENCAP: u64 = 0x8925; /* get/set encapsulations */
pub const SIOCSIFENCAP: u64 = 0x8926;
pub const SIOCGIFHWADDR: u64 = 0x8927; /* Get hardware address */
pub const SIOCGIFSLAVE: u64 = 0x8929; /* Driver slaving support */
pub const SIOCSIFSLAVE: u64 = 0x8930;
pub const SIOCADDMULTI: u64 = 0x8931; /* Multicast address lists */
pub const SIOCDELMULTI: u64 = 0x8932;
pub const SIOCGIFINDEX: u64 = 0x8933; /* name -> if_index mapping */
pub const SIOGIFINDEX: u64 = SIOCGIFINDEX; /* misprint compatibility :-) */
pub const SIOCSIFPFLAGS: u64 = 0x8934; /* set/get extended flags set */
pub const SIOCGIFPFLAGS: u64 = 0x8935;
pub const SIOCDIFADDR: u64 = 0x8936; /* delete PA address */
pub const SIOCSIFHWBROADCAST: u64 = 0x8937; /* set hardware broadcast addr */
pub const SIOCGIFCOUNT: u64 = 0x8938; /* get number of devices */

pub const SIOCGIFBR: u64 = 0x8940; /* Bridging support */
pub const SIOCSIFBR: u64 = 0x8941; /* Set bridging options */

pub const SIOCGIFTXQLEN: u64 = 0x8942; /* Get the tx queue length */
pub const SIOCSIFTXQLEN: u64 = 0x8943; /* Set the tx queue length */

/* ARP cache control calls. */
/* 0x8950 - 0x8952 * obsolete calls, don't re-use */
pub const SIOCDARP: u64 = 0x8953; /* delete ARP table entry */
pub const SIOCGARP: u64 = 0x8954; /* get ARP table entry */
pub const SIOCSARP: u64 = 0x8955; /* set ARP table entry */

/* RARP cache control calls. */
pub const SIOCDRARP: u64 = 0x8960; /* delete RARP table entry */
pub const SIOCGRARP: u64 = 0x8961; /* get RARP table entry */
pub const SIOCSRARP: u64 = 0x8962; /* set RARP table entry */

/* Driver configuration calls */

pub const SIOCGIFMAP: u64 = 0x8970; /* Get device parameters */
pub const SIOCSIFMAP: u64 = 0x8971; /* Set device parameters */

/* DLCI configuration calls */

pub const SIOCADDDLCI: u64 = 0x8980; /* Create new DLCI device */
pub const SIOCDELDLCI: u64 = 0x8981; /* Delete DLCI device */

/* Device private ioctl calls. */

/* These 16 ioctls are available to devices via the do_ioctl() device
vector. Each device should include this file and redefine these
names as their own. Because these are device dependent it is a good
idea _NOT_ to issue them to random objects and hope. */

pub const SIOCDEVPRIVATE: u64 = 0x89F0; /* to 89FF */

/*
 * These 16 ioctl calls are protocol private
 */

pub const SIOCPROTOPRIVATE: u64 = 0x89E0; /* to 89EF */

pub const IFF_UP: u16 = 0x1; /* Interface is up. */
pub const IFF_BROADCAST: u16 = 0x2; /* Broadcast address valid. */
pub const IFF_DEBUG: u16 = 0x4; /* Turn on debugging. */
pub const IFF_LOOPBACK: u16 = 0x8; /* Is a loopback net. */
pub const IFF_POINTOPOINT: u16 = 0x10; /* Interface is point-to-point link. */
pub const IFF_NOTRAILERS: u16 = 0x20; /* Avoid use of trailers. */
pub const IFF_RUNNING: u16 = 0x40; /* Resources allocated. */
pub const IFF_NOARP: u16 = 0x80; /* No address resolution protocol. */
pub const IFF_PROMISC: u16 = 0x100; /* Receive all packets. */

/* Not supported */
pub const IFF_ALLMULTI: u16 = 0x200; /* Receive all multicast packets. */

pub const IFF_MASTER: u16 = 0x400; /* Master of a load balancer. */
pub const IFF_SLAVE: u16 = 0x800; /* Slave of a load balancer. */

pub const IFF_MULTICAST: u16 = 0x1000; /* Supports multicast. */

pub const IFF_PORTSEL: u16 = 0x2000; /* Can set media type. */
pub const IFF_AUTOMEDIA: u16 = 0x4000; /* Auto media select active. */
pub const IFF_DYNAMIC: u16 = 0x8000; /* Dialup device with changing addresses. */
