/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Not standalone. Include only from door/net.c, in the order listed there,
 * after vmlinux.h and the bpf helpers. Lifted verbatim from net.c:1302-1532. */
#ifndef DOOR_NET_PROGS_H
#define DOOR_NET_PROGS_H

/*
 * ===========================================================================
 * Hooks
 * ===========================================================================
 */

/* Inbound TCP, judged at the SYN before any connection state is committed.
 *
 * Runs in softirq: there is no current task, so nothing here may call
 * bpf_get_current_*. Everything needed is already on the request_sock, which
 * tcp_conn_request() fills in via af_ops->init_req() immediately before calling
 * this hook — no sk_buff parsing required. sk is the listening socket.
 *
 * task_is_exempt() is deliberately absent. Ingress is a host-wide policy with
 * no user behind it, so there is no session to exempt. */
SEC("lsm/inet_conn_request")
long BPF_PROG(wax_check_ingress, struct sock *sk, struct sk_buff *skb,
              struct request_sock *req, int ret)
{
    /* Not named ctx: BPF_PROG's expansion already binds that identifier. */
    struct ingress_ctx ic = {};
    __u16 family;

    if (ret) return lsm_ret(ret);
    family = BPF_CORE_READ(req, __req_common.skc_family);
    if (family == AF_INET) {
        /* On a request_sock, skc_daddr is ir_rmt_addr (the client) and
         * skc_rcv_saddr is ir_loc_addr (the address it reached us on). */
        set_v4_mapped(ic.src, BPF_CORE_READ(req, __req_common.skc_daddr));
        set_v4_mapped(ic.local, BPF_CORE_READ(req, __req_common.skc_rcv_saddr));
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&ic.src, req, __req_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&ic.local, req, __req_common.skc_v6_rcv_saddr);
    } else {
        return 0;
    }
    ic.family = (__u8)family;
    ic.lport = BPF_CORE_READ(req, __req_common.skc_num);              /* host order */
    ic.sport = bpf_ntohs(BPF_CORE_READ(req, __req_common.skc_dport)); /* big endian */
    return lsm_ret(check_ingress(&ic));
}

/* socket() and socketpair(). The only hook that sees raw/ICMP sockets before
 * they can do anything, which makes it the practical lever for those: a raw
 * socket has no ports and its sendmsg destinations are weak evidence.
 *
 * A protocol of 0 means "the default for this family and type", which is what
 * socket(AF_INET, SOCK_STREAM, 0) passes. Normalizing it to TCP/UDP here is
 * what makes a {"protocol": "tcp", "permission": create} rule behave the way it
 * reads. SOCK_RAW is left alone: 0 there means IPPROTO_IP, not a default. */
SEC("lsm/socket_create")
long BPF_PROG(wax_check_create, int family, int type, int protocol, int kern, int ret)
{
    struct net_target t = {};

    if (ret) return lsm_ret(ret);
    /* Kernel-internal sockets (NFS, cifs, kernel TLS, ...) are not user policy
     * and must never be blocked. */
    if (kern) return 0;
    if (task_is_exempt()) return 0;

    t.family = (__u8)family;
    t.sock_type = (__u8)type;
    t.protocol = (__u8)protocol;
    if (protocol == 0 && (family == AF_INET || family == AF_INET6)) {
        if (type == SOCK_STREAM) t.protocol = IPPROTO_TCP;
        else if (type == SOCK_DGRAM) t.protocol = IPPROTO_UDP;
    }
    return lsm_ret(check_net_policy(&t, OP_NET_CREATE, NPERM_CREATE));
}

SEC("lsm/socket_bind")
long BPF_PROG(wax_check_bind, struct socket *sock, struct sockaddr *address,
              int addrlen, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(address, addrlen, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_BIND, NPERM_BIND));
}

SEC("lsm/socket_listen")
long BPF_PROG(wax_check_listen, struct socket *sock, int backlog, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    if (read_sock_local(sock, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_LISTEN, NPERM_LISTEN));
}

/* The peer is deliberately absent here: this hook runs before accept()
 * completes, so newsock carries no peer address yet. Inbound connections are
 * therefore judged on the listening socket's own address — which port was
 * opened — and per-peer inbound filtering is out of scope. */
SEC("lsm/socket_accept")
long BPF_PROG(wax_check_accept, struct socket *sock, struct socket *newsock, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    if (read_sock_local(sock, &t, pb->path) < 0) return 0;
    return lsm_ret(check_net_policy(&t, OP_NET_ACCEPT, NPERM_ACCEPT));
}

/* Covers AF_UNIX as well as IP: security_socket_connect runs for every family,
 * and by then the sockaddr has been copied into kernel memory, so a
 * sockaddr_un's sun_path is readable straight from the argument. That is why
 * there is no unix_stream_connect hook here. */
SEC("lsm/socket_connect")
long BPF_PROG(wax_check_connect, struct socket *sock, struct sockaddr *address,
              int addrlen, int ret)
{
    __u32 zero = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    pb = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(address, addrlen, &t, pb->path) < 0) return 0;
    t.is_remote = 1;
    return lsm_ret(check_net_policy(&t, OP_NET_CONNECT, NPERM_CONNECT));
}

/*
 * The only hook on the data path, so it defends itself in three stages:
 *
 *  1. msg_name == NULL means the destination was fixed by connect() and already
 *     judged there. Every TCP send and every connected-UDP send exits here, at
 *     the cost of one field read.
 *  2. An IP destination is looked up in wax_net_verdict_cache, keyed by socket and
 *     destination; a hit for the current policy generation skips the rule scan
 *     entirely. This is what makes a sendto() loop to one collector cheap.
 *  3. Only a cache miss runs the full policy scan, and it caches the result.
 *
 * The cache also throttles events: one record per (socket, destination,
 * generation) instead of one per datagram. AF_UNIX destinations skip the cache
 * because a path does not fit the key, and hashing one risks a collision
 * silently deciding an access.
 */
SEC("lsm/socket_sendmsg")
long BPF_PROG(wax_check_sendmsg, struct socket *sock, struct msghdr *msg,
              int size, int ret)
{
    __u32 zero = 0, gen = 0;
    struct net_target t = {};
    struct net_path_scratch *pb;
    struct net_runtime_config *cfg;
    struct net_cache_key key = {};
    struct net_cache_val *val, nv = {};
    void *name;
    int addrlen, r;

    if (ret) return lsm_ret(ret);
    if (task_is_exempt()) return 0;
    name = BPF_CORE_READ(msg, msg_name);
    if (!name) return 0;
    addrlen = BPF_CORE_READ(msg, msg_namelen);

    pb = bpf_map_lookup_elem(&wax_net_addr_scratch, &zero);
    if (!pb) return 0;
    pb->path[0] = '\0';
    read_sock_meta(sock, &t);
    if (read_sockaddr(name, addrlen, &t, pb->path) < 0) return 0;
    t.is_remote = 1;

    cfg = bpf_map_lookup_elem(&wax_net_runtime_config_map, &zero);
    gen = cfg ? cfg->generation : 0;

    if (t.has_addr && t.sk) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
        __u32 uid = BPF_CORE_READ(task, loginuid.val);
        /* Two people on a shared account have the same login uid, so the
         * session is what tells their verdicts apart. */
        __u32 sid = BPF_CORE_READ(task, sessionid);

        key.sk = t.sk;
        val = bpf_map_lookup_elem(&wax_net_verdict_cache, &key);
        if (val && val->generation == gen && val->uid == uid &&
            val->session_id == sid &&
            val->port == t.port && addrs_equal(val->addr, t.addr))
            return lsm_ret(val->verdict ? -13 /* EACCES */ : 0);

        r = check_net_policy(&t, OP_NET_SEND, NPERM_CONNECT);
        nv.generation = gen;
        nv.uid = uid;
        nv.session_id = sid;
        __builtin_memcpy(nv.addr, t.addr, 16);
        nv.port = t.port;
        nv.verdict = r ? 1 : 0;
        nv.emitted = 1;
        bpf_map_update_elem(&wax_net_verdict_cache, &key, &nv, BPF_ANY);
        return lsm_ret(r);
    }
    return lsm_ret(check_net_policy(&t, OP_NET_SEND, NPERM_CONNECT));
}

/* Drop the socket's cached verdict before the kernel can hand its memory to a
 * new socket. Without this the cache key — a bare struct sock pointer — would
 * alias across sockets and leak one process's verdict to another. */
SEC("lsm/sk_free_security")
void BPF_PROG(wax_check_sk_free, struct sock *sk)
{
    struct net_cache_key key = { .sk = (__u64)(unsigned long)sk };

    bpf_map_delete_elem(&wax_net_verdict_cache, &key);
}
#endif /* DOOR_NET_PROGS_H */
