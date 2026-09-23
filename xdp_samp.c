#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * SAMP-AntiDDoS
 * Lite XDP filter for SA-MP / open.mp.
 *
 * Xoce - Hostly US, LLC.
 * Copyright (c) 2026 Xoce.
 *
 * This is the public Lite build.
 */

#ifndef gameport
#define gameport 7777
#endif

#define qh      11
#define cht     5000000000ULL
#define admit   180000000000ULL
#define touch   1000000000ULL
#define retry   500000000ULL

#define fch     1
#define fest    3

#define spass   0
#define sqry    1
#define stx     2
#define sok     3
#define snew    4
#define sretry  5
#define sdq     6
#define sother  7
#define scrypt  8
#define sdc     9
#define sbogon  10
#define sipudp  11
#define sfrag   12
#define sexp    13
#define ssec    14
#define scool   15

struct vlan_hdr {
    __be16 tci;
    __be16 next;
};

struct flow {
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
};

struct flow_st {
    __u64 ts;       /* created / last gameplay touch */
    __u64 last_tx;  /* last challenge reply; challenge state only */
    __u32 orig4;
    __u16 cookie;
    __u8  state;
    __u8  pad;
};

struct cookie_secret {
    __u64 k0;
    __u64 k1;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow);
    __type(value, struct flow_st);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow);
    __type(value, struct flow_st);
} challenges SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cookie_secret);
} secret SEC(".maps");

static const __u8 samp_dec_key[256] = {
    0xB4, 0x62, 0x07, 0xE5, 0x9D, 0xAF, 0x63, 0xDD, 0xE3, 0xD0, 0xCC, 0xFE, 0xDC, 0xDB, 0x6B, 0x2E,
    0x6A, 0x40, 0xAB, 0x47, 0xC9, 0xD1, 0x53, 0xD5, 0x20, 0x91, 0xA5, 0x0E, 0x4A, 0xDF, 0x18, 0x89,
    0xFD, 0x6F, 0x25, 0x12, 0xB7, 0x13, 0x77, 0x00, 0x65, 0x36, 0x6D, 0x49, 0xEC, 0x57, 0x2A, 0xA9,
    0x11, 0x5F, 0xFA, 0x78, 0x95, 0xA4, 0xBD, 0x1E, 0xD9, 0x79, 0x44, 0xCD, 0xDE, 0x81, 0xEB, 0x09,
    0x3E, 0xF6, 0xEE, 0xDA, 0x7F, 0xA3, 0x1A, 0xA7, 0x2D, 0xA6, 0xAD, 0xC1, 0x46, 0x93, 0xD2, 0x1B,
    0x9C, 0xAA, 0xD7, 0x4E, 0x4B, 0x4D, 0x4C, 0xF3, 0xB8, 0x34, 0xC0, 0xCA, 0x88, 0xF4, 0x94, 0xCB,
    0x04, 0x39, 0x30, 0x82, 0xD6, 0x73, 0xB0, 0xBF, 0x22, 0x01, 0x41, 0x6E, 0x48, 0x2C, 0xA8, 0x75,
    0xB1, 0x0A, 0xAE, 0x9F, 0x27, 0x80, 0x10, 0xCE, 0xF0, 0x29, 0x28, 0x85, 0x0D, 0x05, 0xF7, 0x35,
    0xBB, 0xBC, 0x15, 0x06, 0xF5, 0x60, 0x71, 0x03, 0x1F, 0xEA, 0x5A, 0x33, 0x92, 0x8D, 0xE7, 0x90,
    0x5B, 0xE9, 0xCF, 0x9E, 0xD3, 0x5D, 0xED, 0x31, 0x1C, 0x0B, 0x52, 0x16, 0x51, 0x0F, 0x86, 0xC5,
    0x68, 0x9B, 0x21, 0x0C, 0x8B, 0x42, 0x87, 0xFF, 0x4F, 0xBE, 0xC8, 0xE8, 0xC7, 0xD4, 0x7A, 0xE0,
    0x55, 0x2F, 0x8A, 0x8E, 0xBA, 0x98, 0x37, 0xE4, 0xB2, 0x38, 0xA1, 0xB6, 0x32, 0x83, 0x3A, 0x7B,
    0x84, 0x3C, 0x61, 0xFB, 0x8C, 0x14, 0x3D, 0x43, 0x3B, 0x1D, 0xC3, 0xA2, 0x96, 0xB3, 0xF8, 0xC4,
    0xF2, 0x26, 0x2B, 0xD8, 0x7C, 0xFC, 0x23, 0x24, 0x66, 0xEF, 0x69, 0x64, 0x50, 0x54, 0x59, 0xF1,
    0xA0, 0x74, 0xAC, 0xC6, 0x7D, 0xB5, 0xE6, 0xE2, 0xC2, 0x7E, 0x67, 0x17, 0x5E, 0xE1, 0xB9, 0x3F,
    0x6C, 0x70, 0x08, 0x99, 0x45, 0x56, 0x76, 0xF9, 0x9A, 0x97, 0x19, 0x72, 0x5C, 0x02, 0x8F, 0x58
};

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        (*v)++;
}

static __always_inline void load_secret(struct cookie_secret *out)
{
    __u32 zero = 0;
    struct cookie_secret *s = bpf_map_lookup_elem(&secret, &zero);

    if (s && (s->k0 || s->k1)) {
        *out = *s;
        return;
    }

    out->k0 = ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
    out->k1 = ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
    if (!(out->k0 || out->k1)) {
        out->k0 = 0x736f6d6570736575ULL;
        out->k1 = 0x646f72616e646f6dULL;
    }

    bpf_map_update_elem(&secret, &zero, out, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&secret, &zero);
    if (s && (s->k0 || s->k1))
        *out = *s;
    bump(ssec);
}

#define rol64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define sipround(v0, v1, v2, v3) do {           (v0) += (v1); (v1) = rol64((v1), 13);     (v1) ^= (v0); (v0) = rol64((v0), 32);     (v2) += (v3); (v3) = rol64((v3), 16);     (v3) ^= (v2);                                (v0) += (v3); (v3) = rol64((v3), 21);     (v3) ^= (v0);                                (v2) += (v1); (v1) = rol64((v1), 17);     (v1) ^= (v2); (v2) = rol64((v2), 32); } while (0)

static __always_inline void sip_compress(__u64 *v0, __u64 *v1,
                                         __u64 *v2, __u64 *v3, __u64 m)
{
    *v3 ^= m;
    sipround(*v0, *v1, *v2, *v3);
    sipround(*v0, *v1, *v2, *v3);
    *v0 ^= m;
}

static __always_inline __u16 flow_cookie(const struct flow *f, __u64 now,
                                         __u32 orig4)
{
    struct cookie_secret sec = {};
    __u64 v0, v1, v2, v3, m0, m1, m2, b, out;
    __u32 epoch = (__u32)(now / 2000000000ULL);
    __u16 ret;

    load_secret(&sec);

    v0 = 0x736f6d6570736575ULL ^ sec.k0;
    v1 = 0x646f72616e646f6dULL ^ sec.k1;
    v2 = 0x6c7967656e657261ULL ^ sec.k0;
    v3 = 0x7465646279746573ULL ^ sec.k1;

    m0 = ((__u64)bpf_ntohl(f->sip) << 32) | (__u64)bpf_ntohl(f->dip);
    m1 = ((__u64)bpf_ntohs(f->sport) << 48) |
         ((__u64)bpf_ntohs(f->dport) << 32) |
         0x53414d50ULL;
    m2 = ((__u64)epoch << 32) | (__u64)orig4;

    sip_compress(&v0, &v1, &v2, &v3, m0);
    sip_compress(&v0, &v1, &v2, &v3, m1);
    sip_compress(&v0, &v1, &v2, &v3, m2);

    b = 24ULL << 56;
    sip_compress(&v0, &v1, &v2, &v3, b);
    v2 ^= 0xff;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    out = v0 ^ v1 ^ v2 ^ v3;

    ret = (__u16)(out ^ (out >> 16) ^ (out >> 32) ^ (out >> 48));
    return ret ? ret : 1;
}

static __attribute__((noinline)) __u8 samp_dec_lookup(__u32 idx)
{
    idx &= 0xffU;
    return samp_dec_key[idx];
}

static __always_inline int samp_decrypt4(const __u8 *pl, const void *payload_end,
                                         __u16 dport_be,
                                         __u8 *msg, __u16 *xord)
{
    __u16 dport;
    __u8 port, d0, d1, d2;

    if (pl + 4 > (const __u8 *)payload_end)
        return 0;

    dport = bpf_ntohs(dport_be);
    port = (__u8)(dport ^ 0xCC);

    d0 = samp_dec_lookup((__u32)pl[1]);
    d1 = samp_dec_lookup((__u32)pl[2] ^ (__u32)port);
    d2 = samp_dec_lookup((__u32)pl[3]);

    if (pl[0] != ((__u8)(d0 & 0xAA) ^
                  (__u8)(d1 & 0xAA) ^
                  (__u8)(d2 & 0xAA)))
        return 0;

    *msg = d0;
    *xord = (__u16)d1 | ((__u16)d2 << 8);
    return 1;
}

static __always_inline int cookie_matches(__u16 xord, __u16 cookie)
{
    return (xord ^ 0x6969) == cookie || (xord ^ 0x6D70) == cookie;
}

static __always_inline int bad_wan_src(__u32 saddr, __u16 sport_be)
{
    __u32 a = bpf_ntohl(saddr);
    __u16 sp;

    if (a < 0x01000000) return 1;
    if ((a & 0xff000000) == 0x7f000000) return 1;
    if ((a & 0xff000000) == 0x0a000000) return 1;
    if ((a & 0xfff00000) == 0xac100000) return 1;
    if ((a & 0xffff0000) == 0xc0a80000) return 1;
    if ((a & 0xffff0000) == 0xa9fe0000) return 1;
    if ((a & 0xffc00000) == 0x64400000) return 1;
    if ((a & 0xffffff00) == 0xc0000200) return 1;
    if ((a & 0xfffe0000) == 0xc6120000) return 1;
    if ((a & 0xffffff00) == 0xc6336400) return 1;
    if ((a & 0xffffff00) == 0xcb007100) return 1;
    if (a >= 0xe0000000) return 1;

    sp = bpf_ntohs(sport_be);
    switch (sp) {
    case 0: case 19: case 53: case 123: case 137: case 138:
    case 161: case 389: case 1900: case 5353: case 11211:
        return 1;
    default:
        return 0;
    }
}

static __always_inline void ip_csum(struct iphdr *ip)
{
    __u32 acc = 0;
    __u16 *p = (__u16 *)ip;
    int i;

    ip->check = 0;
#pragma unroll
    for (i = 0; i < 10; i++)
        acc += bpf_ntohs(p[i]);

    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);
    ip->check = bpf_htons((__u16)~acc);
}

static __always_inline void swap_l2l3l4(struct ethhdr *eth,
                                        struct iphdr *ip,
                                        struct udphdr *udp)
{
    unsigned char mac[6];
    __u32 a;
    __u16 p;

    __builtin_memcpy(mac, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, mac, 6);

    a = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = a;

    p = udp->source;
    udp->source = udp->dest;
    udp->dest = p;
    udp->check = 0;
}

static __always_inline int xdp_len(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int n = (int)((char *)data_end - (char *)data);
    asm volatile("" : "+r"(n));
    return n;
}

static __always_inline int resize_l2(struct xdp_md *ctx, __u16 payload, int l2_len)
{
    int orig = xdp_len(ctx);
    int neu = l2_len + 20 + 8 + (int)payload;
    int delta;

    asm volatile("" : "+r"(orig), "+r"(neu));
    delta = neu - orig;
    if (!delta)
        return 0;
    return bpf_xdp_adjust_tail(ctx, delta);
}

static __always_inline int reparse_l2(struct xdp_md *ctx, int l2_len,
                                      struct ethhdr **eth,
                                      struct iphdr **ip,
                                      struct udphdr **udp,
                                      __u8 **pl, void **data_end)
{
    __u8 *data = (void *)(long)ctx->data;
    __u8 *p;

    *data_end = (void *)(long)ctx->data_end;
    *eth = (struct ethhdr *)data;
    if ((void *)(*eth + 1) > *data_end)
        return -1;

    if (l2_len == 14) p = data + 14;
    else if (l2_len == 18) p = data + 18;
    else if (l2_len == 22) p = data + 22;
    else return -1;

    if (p + sizeof(struct iphdr) > (__u8 *)*data_end)
        return -1;
    *ip = (struct iphdr *)p;
    if ((*ip)->version != 4 || (*ip)->ihl != 5)
        return -1;

    p += sizeof(struct iphdr);
    if (p + sizeof(struct udphdr) > (__u8 *)*data_end)
        return -1;
    *udp = (struct udphdr *)p;
    *pl = p + sizeof(struct udphdr);
    return 0;
}

static __always_inline int tx_cookie(struct xdp_md *ctx, int l2_len, __u16 ck)
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    __u8 *pl;
    void *data_end;

    if (resize_l2(ctx, 3, l2_len))
        return XDP_DROP;
    if (reparse_l2(ctx, l2_len, &eth, &ip, &udp, &pl, &data_end))
        return XDP_DROP;
    if (pl + 3 > (__u8 *)data_end)
        return XDP_DROP;

    swap_l2l3l4(eth, ip, udp);
    pl[0] = 0x1A;
    pl[1] = ck & 0xff;
    pl[2] = (ck >> 8) & 0xff;

    ip->ttl = 64;
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = 0;
    ip->tot_len = bpf_htons(20 + 8 + 3);
    udp->len = bpf_htons(8 + 3);
    ip_csum(ip);
    bump(stx);
    return XDP_TX;
}

static __always_inline int issue_challenge(struct xdp_md *ctx, int l2_len,
                                           const struct flow *fk,
                                           __u32 orig4, __u64 now)
{
    __u16 cookie = flow_cookie(fk, now, orig4);
    struct flow_st neu = {
        .ts = now,
        .last_tx = now,
        .orig4 = orig4,
        .cookie = cookie,
        .state = fch,
        .pad = 0,
    };

    bpf_map_update_elem(&challenges, fk, &neu, BPF_ANY);
    bump(snew);
    return tx_cookie(ctx, l2_len, cookie);
}

SEC("xdp")
int xdp_samp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct flow fk = {};
    struct flow_st *fst, *ch;
    __u8 *pl, *ip_end, *p, op, msg;
    __u32 embed, orig4;
    __u16 proto, iplen, ulen, dport_host, xord;
    __u64 now;
    int pay, l2_len = 14;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = eth->h_proto;
    p = (__u8 *)(eth + 1);

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(0x88a8))
            break;
        struct vlan_hdr *vh = (struct vlan_hdr *)p;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        proto = vh->next;
        p += sizeof(*vh);
        l2_len += 4;
    }

    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    if (p + sizeof(struct iphdr) > (__u8 *)data_end) {
        bump(sipudp);
        return XDP_DROP;
    }

    ip = (struct iphdr *)p;
    if (ip->version != 4 || ip->ihl != 5) {
        bump(sipudp);
        return XDP_DROP;
    }
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    if (ip->frag_off & bpf_htons(0x3fff)) {
        bump(sfrag);
        return XDP_DROP;
    }

    iplen = bpf_ntohs(ip->tot_len);
    if (iplen < sizeof(struct iphdr) + sizeof(struct udphdr)) {
        bump(sipudp);
        return XDP_DROP;
    }
    ip_end = (__u8 *)ip + iplen;
    if (ip_end > (__u8 *)data_end) {
        bump(sipudp);
        return XDP_DROP;
    }

    p += sizeof(struct iphdr);
    if (p + sizeof(struct udphdr) > ip_end) {
        bump(sipudp);
        return XDP_DROP;
    }
    udp = (struct udphdr *)p;

    if (udp->dest != bpf_htons(gameport))
        return XDP_PASS;

    pl = p + sizeof(struct udphdr);
    ulen = bpf_ntohs(udp->len);
    if (ulen < sizeof(struct udphdr) || ulen != iplen - sizeof(struct iphdr)) {
        bump(sipudp);
        return XDP_DROP;
    }
    pay = (int)ulen - (int)sizeof(struct udphdr);
    if (pl + pay != ip_end) {
        bump(sipudp);
        return XDP_DROP;
    }

    if (bad_wan_src(ip->saddr, udp->source)) {
        bump(sbogon);
        return XDP_DROP;
    }

    /* Queries: i/p are allowed after validation; everything else is dropped. */
    if (pay >= 4 && pl[0] == 'S' && pl[1] == 'A' && pl[2] == 'M' && pl[3] == 'P') {
        if (pay < qh || pl + qh > ip_end) {
            bump(sdq);
            return XDP_DROP;
        }
        __builtin_memcpy(&embed, pl + 4, sizeof(embed));
        if (embed != ip->daddr) {
            bump(sdq);
            return XDP_DROP;
        }
        dport_host = bpf_ntohs(udp->dest);
        if ((__u16)(pl[8] | ((__u16)pl[9] << 8)) != dport_host) {
            bump(sdq);
            return XDP_DROP;
        }
        op = pl[10];
        if (op == 'i' && pay == qh) {
            bump(sqry);
            return XDP_PASS;
        }
        if (op == 'p' && pay == qh + 4 && pl + qh + 4 <= ip_end) {
            bump(sqry);
            return XDP_PASS;
        }
        bump(sdq);
        return XDP_DROP;
    }

    fk.sip = ip->saddr;
    fk.dip = ip->daddr;
    fk.sport = udp->source;
    fk.dport = udp->dest;

    fst = bpf_map_lookup_elem(&flows, &fk);
    if (fst) {
        now = bpf_ktime_get_ns();
        if (fst->state == fest && now - fst->ts <= admit) {
            if (now - fst->ts >= touch) {
                fst->ts = now;
                bump(spass);
            }
            return XDP_PASS;
        }
        bpf_map_delete_elem(&flows, &fk);
    }

    if (pay != 4) {
        bump(sother);
        return XDP_DROP;
    }

    msg = 0;
    xord = 0;
    if (!samp_decrypt4(pl, ip_end, udp->dest, &msg, &xord) || msg != 0x18) {
        bump(scrypt);
        return XDP_DROP;
    }

    __builtin_memcpy(&orig4, pl, sizeof(orig4));
    now = bpf_ktime_get_ns();

    ch = bpf_map_lookup_elem(&challenges, &fk);
    if (ch && (ch->state != fch || now - ch->ts > cht)) {
        bpf_map_delete_elem(&challenges, &fk);
        bump(sexp);
        ch = 0;
    }

    if (ch) {
        if (cookie_matches(xord, ch->cookie)) {
            struct flow_st neu = {
                .ts = now,
                .last_tx = 0,
                .orig4 = ch->orig4,
                .cookie = ch->cookie,
                .state = fest,
                .pad = 0,
            };
            __builtin_memcpy(pl, &ch->orig4, sizeof(ch->orig4));
            udp->check = 0;
            bpf_map_update_elem(&flows, &fk, &neu, BPF_ANY);
            bpf_map_delete_elem(&challenges, &fk);
            bump(sok);
            return XDP_PASS;
        }
        if (orig4 == ch->orig4) {
            bump(sretry);
            if (now - ch->last_tx < retry) {
                bump(scool);
                return XDP_DROP;
            }
            ch->last_tx = now;
            return tx_cookie(ctx, l2_len, ch->cookie);
        }
        bump(sdc);
        return XDP_DROP;
    }

    return issue_challenge(ctx, l2_len, &fk, orig4, now);
}

char _license[] SEC("license") = "GPL";
