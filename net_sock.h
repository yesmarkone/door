/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:611-774. */
#ifndef DOOR_NET_SOCK_H
#define DOOR_NET_SOCK_H

/* Everything one hook learned about the socket it is deciding on. */
struct net_target {
    __u8 addr[16];      /* normalized peer (connect/sendmsg) or local address */
    __u64 sk;           /* struct sock *, for the verdict cache key */
    const char *path;   /* AF_UNIX socket path, or NULL */
    __u32 path_len;
    __u16 port;
    __u8 family;
    __u8 protocol;
    __u8 sock_type;
    __u8 has_addr;      /* an IP address/port was resolved */
    __u8 is_remote;     /* address describes the peer, not the local end */
};

static __always_inline int addrs_equal(const __u8 *a, const __u8 *b)
{
#pragma unroll
    for (int i = 0; i < 16; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

static __always_inline void set_v4_mapped(__u8 *a16, __be32 v4)
{
    __builtin_memset(a16, 0, 10);
    a16[10] = 0xff;
    a16[11] = 0xff;
    __builtin_memcpy(a16 + 12, &v4, 4);
}

/* Copy a unix socket path out of a kernel-resident sockaddr_un. Abstract
 * sockets (a leading NUL) are spelled '@name', matching how ss(8) prints them,
 * so policies can target them with a "@*" pattern. Returns the string length. */
static __always_inline __u32 read_unix_path(const void *sa, int addrlen, char *out)
{
    const char *sun_path = (const char *)sa + SUN_PATH_OFF;
    char first = 0;
    long len;

    out[0] = '\0';
    if (addrlen <= SUN_PATH_OFF) return 0; /* autobind: unnamed socket */
    if (bpf_probe_read_kernel(&first, 1, sun_path) < 0) return 0;
    if (first == '\0') {
        out[0] = '@';
        len = bpf_probe_read_kernel_str(&out[1], UNIX_PATH_MAX, sun_path + 1);
        if (len <= 0) {
            out[0] = '\0';
            return 0;
        }
        return (__u32)len; /* 1 for '@' + (len - 1) name bytes */
    }
    len = bpf_probe_read_kernel_str(out, UNIX_PATH_MAX, sun_path);
    if (len <= 0) {
        out[0] = '\0';
        return 0;
    }
    return (__u32)len - 1;
}

/* Decode the sockaddr a syscall handed in. bind/connect/sendmsg all receive it
 * already copied into kernel memory (move_addr_to_kernel runs before the LSM
 * hook), so probe_read_kernel is correct for every one of them. Fields are read
 * individually rather than as whole structs so a short addrlen still works. */
static __always_inline int read_sockaddr(const void *sa, int addrlen,
                                         struct net_target *t, char *pathbuf)
{
    __u16 fam = 0;

    if (!sa || addrlen < 2) return -1;
    if (bpf_probe_read_kernel(&fam, sizeof(fam), (const char *)sa + SA_FAMILY_OFF) < 0)
        return -1;

    if (fam == AF_INET) {
        __be16 port = 0;
        __be32 v4 = 0;

        if (addrlen < SIN_ADDR_OFF + 4) return -1;
        if (bpf_probe_read_kernel(&port, 2, (const char *)sa + SIN_PORT_OFF) < 0) return -1;
        if (bpf_probe_read_kernel(&v4, 4, (const char *)sa + SIN_ADDR_OFF) < 0) return -1;
        set_v4_mapped(t->addr, v4);
        t->port = bpf_ntohs(port);
        t->family = AF_INET;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_INET6) {
        __be16 port = 0;

        if (addrlen < SIN6_ADDR_OFF + 16) return -1;
        if (bpf_probe_read_kernel(&port, 2, (const char *)sa + SIN6_PORT_OFF) < 0) return -1;
        if (bpf_probe_read_kernel(t->addr, 16, (const char *)sa + SIN6_ADDR_OFF) < 0) return -1;
        t->port = bpf_ntohs(port);
        t->family = AF_INET6;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_UNIX) {
        t->family = AF_UNIX;
        t->path = pathbuf;
        t->path_len = read_unix_path(sa, addrlen, pathbuf);
        return 0;
    }
    /* Other families (netlink, packet, ...) still get family-level matching. */
    t->family = (__u8)fam;
    return 0;
}

/* Socket-level attributes that every hook wants, independent of any address. */
static __always_inline void read_sock_meta(struct socket *sock, struct net_target *t)
{
    struct sock *sk;

    if (!sock) return;
    t->sock_type = (__u8)BPF_CORE_READ(sock, type);
    sk = BPF_CORE_READ(sock, sk);
    if (!sk) return;
    t->sk = (__u64)(unsigned long)sk;
    t->protocol = (__u8)BPF_CORE_READ(sk, sk_protocol);
}

/* Resolve the socket's local address, for hooks that get no sockaddr argument
 * (listen, accept). skc_num is already host byte order. */
static __always_inline int read_sock_local(struct socket *sock, struct net_target *t,
                                           char *pathbuf)
{
    struct sock *sk;
    __u16 fam;

    read_sock_meta(sock, t);
    sk = BPF_CORE_READ(sock, sk);
    if (!sk) return -1;
    fam = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (fam == AF_INET) {
        set_v4_mapped(t->addr, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        t->port = BPF_CORE_READ(sk, __sk_common.skc_num);
        t->family = AF_INET;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_INET6) {
        BPF_CORE_READ_INTO(t->addr, sk, __sk_common.skc_v6_rcv_saddr);
        t->port = BPF_CORE_READ(sk, __sk_common.skc_num);
        t->family = AF_INET6;
        t->has_addr = 1;
        return 0;
    }
    if (fam == AF_UNIX) {
        struct unix_sock *u = (struct unix_sock *)sk;
        struct unix_address *ua = BPF_CORE_READ(u, addr);

        t->family = AF_UNIX;
        if (ua) {
            int alen = BPF_CORE_READ(ua, len);

            t->path = pathbuf;
            t->path_len = read_unix_path(&ua->name[0], alen, pathbuf);
        }
        return 0;
    }
    t->family = (__u8)fam;
    return 0;
}

#endif /* DOOR_NET_SOCK_H */
