/*
 * PDR Hash Bypass — O(1) TEID/UE-IP hash → small candidate scan
 *
 * Replaces the 515 ns PartitionSort classifier for the common case where
 * PDRs are uniquely identified by TEID (UL) or UE-IP (DL), with a short
 * precedence-sorted candidate list for SDF 5-tuple differentiation.
 *
 * 3GPP-correct: evaluates ALL matching PDRs for a given TEID/UE-IP and
 * selects by precedence + QFI/SDF match. The hash is an acceleration
 * structure, not a change in classification semantics.
 *
 * Both UPF-C (writer) and UPF-U (reader) include this header.
 *
 * Lives in onvm/upf/ (shared infrastructure) so both binaries can
 * include it cleanly via  #include "pdr_hash_bypass.h"
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>         /* SSE 4.2 CRC32 hardware hash          */

#include "updk/rule_pdr.h"        /* UPDK_PDR  — resolves via onvm/updk/ */
#include "classifier_wrapper.h"   /* ps_packet_t — resolves via 5gc/classifiers/ */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Tunable limits ────────────────────────────────────────────────── */
#define PHB_TEID_BUCKETS   512   /* power of 2 — covers up to ~400 UEs */
#define PHB_UEIP_BUCKETS   512
#define PHB_MAX_CANDIDATES   8   /* max PDRs per TEID or UE-IP           */

/* ── Candidate entry (one per PDR in a bucket) ─────────────────────── */
typedef struct {
    const UPDK_PDR *pdr;         /* pointer to hugepage-resident PDR       */
    uint32_t  precedence;        /* lower value = higher priority          */
    uint32_t  teid;              /* TEID (UL only, 0 for DL)               */
    uint32_t  ue_ip;             /* UE IP in host byte order               */
    uint8_t   qfi;               /* QFI filter (0 = wildcard)              */
    uint8_t   has_sdf;           /* 1 if SDF 5-tuple filter is present     */
    uint8_t   sdf_proto;         /* IP protocol from SDF (0 = wildcard)    */
    uint16_t  sdf_src_port;      /* SDF source port (0 = wildcard)         */
    uint16_t  sdf_dst_port;      /* SDF destination port (0 = wildcard)    */
    uint32_t  sdf_src_ip;        /* SDF source IP host order (0 = any)     */
    uint32_t  sdf_dst_ip;        /* SDF dest IP host order (0 = any)       */
    uint8_t   sdf_src_pref;      /* SDF source prefix length (32 = exact)  */
    uint8_t   sdf_dst_pref;      /* SDF dest prefix length (32 = exact)    */
    bool      is_uplink;
} phb_candidate_t;

/* ── Bucket: small array of candidates, sorted by precedence ───────── */
typedef struct {
    uint32_t         key;                          /* TEID or UE-IP       */
    uint8_t          count;                        /* 0 = empty slot      */
    uint8_t          overflow;                     /* 1 = incomplete, must
                                                    * fall back to full
                                                    * classifier           */
    phb_candidate_t  cands[PHB_MAX_CANDIDATES];    /* sorted by precedence*/
} phb_bucket_t;

/* ── The full bypass table (one per classifier snapshot) ───────────── */
typedef struct {
    phb_bucket_t teid_tbl[PHB_TEID_BUCKETS];   /* UL: TEID → candidates  */
    phb_bucket_t ueip_tbl[PHB_UEIP_BUCKETS];   /* DL: UE-IP → candidates */
} phb_table_t;


/* ══════════════════════════════════════════════════════════════════════
 *  Builder API (UPF-C side — called during UpfClsRebuildAndPublish)
 * ══════════════════════════════════════════════════════════════════════ */

static inline phb_table_t *phb_create(void) {
    phb_table_t *t = (phb_table_t *)rte_zmalloc("phb_table",
                                                  sizeof(phb_table_t),
                                                  RTE_CACHE_LINE_SIZE);
    return t;
}

static inline void phb_destroy(phb_table_t *t) {
    if (t) rte_free(t);
}

/* Hash function — hardware-accelerated CRC32 (SSE 4.2 instruction)
 * Uses DPDK's rte_hash_crc_4byte() which compiles to a single CRC32
 * instruction on x86.  Provides excellent distribution for integer keys
 * with minimal latency (~3 cycles). */
static inline uint32_t phb_hash32(uint32_t key, uint32_t n_buckets) {
    return rte_hash_crc_4byte(key, 0) & (n_buckets - 1);
}

/* Insert a candidate into the appropriate bucket, keeping sorted by precedence.
 * Returns 0 on success, -1 if bucket is full. */
static inline int
phb_insert_candidate(phb_bucket_t *tbl, uint32_t n_buckets,
                     uint32_t key, const phb_candidate_t *cand)
{
    uint32_t idx = phb_hash32(key, n_buckets);
    uint32_t start = idx;

    /* Open-addressing linear probe to find the bucket for this key */
    for (;;) {
        phb_bucket_t *b = &tbl[idx];
        if (b->count == 0) {
            /* Empty bucket — claim it */
            b->key = key;
            b->cands[0] = *cand;
            b->count = 1;
            return 0;
        }
        if (b->key == key) {
            /* Found existing bucket for this key — insert sorted by precedence */
            if (b->count >= PHB_MAX_CANDIDATES) {
                b->overflow = 1;   /* poison: not all candidates fit,
                                    * lookup must fall back to full
                                    * classifier for this key          */
                return -1;
            }

            /* Insertion sort: find position */
            int pos = b->count;
            for (int i = 0; i < b->count; i++) {
                if (cand->precedence < b->cands[i].precedence) {
                    pos = i;
                    break;
                }
            }
            /* Shift right */
            for (int i = b->count; i > pos; i--)
                b->cands[i] = b->cands[i - 1];
            b->cands[pos] = *cand;
            b->count++;
            return 0;
        }
        /* Collision — linear probe */
        idx = (idx + 1) % n_buckets;
        if (idx == start)
            return -1;   /* table full */
    }
}

/* Parse "A.B.C.D[/P]" into host-order IP + prefix length.
 * No /P defaults to /32 (exact host).  Returns 0 with *pref_out=0 on error.
 * Pure C mirror of the C++ parse_ip_prefix() in upf_cls_adapter.cpp. */
static inline uint32_t
phb_parse_ip_prefix(const char *s, uint8_t *pref_out)
{
    *pref_out = 0;
    if (!s || !*s) return 0;

    char buf[32];
    size_t len = strlen(s);
    if (len >= sizeof(buf)) return 0;
    memcpy(buf, s, len + 1);

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int p = atoi(slash + 1);
        *pref_out = (p > 0 && p <= 32) ? (uint8_t)p : 32;
    } else {
        *pref_out = 32;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) {
        *pref_out = 0;
        return 0;
    }
    return ntohl(a.s_addr);   /* host byte order */
}

/* Parse a 3GPP flow description (IPFilterRule per TS 29.212 / RFC 6733)
 * into the candidate's SDF fields for per-packet matching.
 *
 * Format:  action dir proto from src [srcport] to dst [dstport]
 *
 * Examples:
 *   "permit out ip from assigned to any"
 *   "permit out 17 from 10.60.0.1 5060 to any"
 *   "permit in ip from any to assigned"
 *
 * Runs on UPF-C at PDR build time — never per-packet.
 * c->ue_ip must already be set before calling this function. */
static inline void
phb_parse_flow_description(const char *fd, phb_candidate_t *c)
{
    if (!fd || !*fd) return;

    /* Local copy — strtok_r modifies the buffer */
    char buf[64];
    size_t fdlen = strlen(fd);
    if (fdlen >= sizeof(buf)) fdlen = sizeof(buf) - 1;
    memcpy(buf, fd, fdlen);
    buf[fdlen] = '\0';

    char *saveptr = NULL;
    char *tok;

    /* Token 1: action (permit/deny) — skip */
    tok = strtok_r(buf, " ", &saveptr);
    if (!tok) return;

    /* Token 2: direction (in/out) — skip (is_uplink from PDR) */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;

    /* Token 3: protocol — "ip" = any (0), or numeric (6=TCP, 17=UDP) */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;
    c->sdf_proto = (strcmp(tok, "ip") == 0) ? 0 : (uint8_t)atoi(tok);

    /* Token 4: "from" keyword */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;

    /* Token 5: source address — "any", "assigned", or "A.B.C.D[/P]" */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;
    if (strcmp(tok, "any") == 0) {
        c->sdf_src_ip   = 0;
        c->sdf_src_pref = 0;
    } else if (strcmp(tok, "assigned") == 0) {
        c->sdf_src_ip   = c->ue_ip;
        c->sdf_src_pref = c->ue_ip ? 32 : 0;
    } else {
        c->sdf_src_ip = phb_parse_ip_prefix(tok, &c->sdf_src_pref);
    }

    /* Token 6: source port (digit) or "to" keyword */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;
    if (strcmp(tok, "to") != 0) {
        c->sdf_src_port = (uint16_t)atoi(tok);
        tok = strtok_r(NULL, " ", &saveptr);   /* must be "to" */
        if (!tok) return;
    }

    /* Token 7/8: destination address */
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) return;
    if (strcmp(tok, "any") == 0) {
        c->sdf_dst_ip   = 0;
        c->sdf_dst_pref = 0;
    } else if (strcmp(tok, "assigned") == 0) {
        c->sdf_dst_ip   = c->ue_ip;
        c->sdf_dst_pref = c->ue_ip ? 32 : 0;
    } else {
        c->sdf_dst_ip = phb_parse_ip_prefix(tok, &c->sdf_dst_pref);
    }

    /* Token 9: optional destination port */
    tok = strtok_r(NULL, " ", &saveptr);
    if (tok && tok[0] >= '0' && tok[0] <= '9') {
        c->sdf_dst_port = (uint16_t)atoi(tok);
    }
}

/* Add a PDR to the bypass table.
 * Extracts TEID/UE-IP/QFI/SDF from the UPDK_PDR and inserts into
 * the appropriate hash table (teid_tbl for UL, ueip_tbl for DL). */
static inline int
phb_add_pdr(phb_table_t *t, const UPDK_PDR *pdr, bool is_uplink)
{
    phb_candidate_t cand;
    memset(&cand, 0, sizeof(cand));

    cand.pdr        = pdr;
    cand.precedence = pdr->precedence;
    cand.is_uplink  = is_uplink;

    /* Extract TEID */
    if (pdr->flags.pdi && pdr->pdi.flags.fTeid)
        cand.teid = pdr->pdi.fTeid.teid;

    /* Extract UE IP (host byte order) */
    if (pdr->flags.pdi && pdr->pdi.flags.ueIpAddress && pdr->pdi.ueIpAddress.flags.v4)
        cand.ue_ip = ntohl(pdr->pdi.ueIpAddress.ipv4.s_addr);

    /* Extract QFI */
    if (pdr->flags.pdi && pdr->pdi.flags.qfi)
        cand.qfi = pdr->pdi.qfi;

    /* Parse SDF flow description into candidate's 5-tuple fields.
     * The flow description string (e.g. "permit out 17 from 10.60.0.1 5060
     * to any") is available on the UPDK_PDR at build time.  We parse it
     * once here so that per-packet phb_match_sdf() is pure register
     * comparisons (~2-3 ns) with no string work. */
    if (pdr->flags.pdi && pdr->pdi.flags.sdfFilter && pdr->pdi.sdfFilter.flags.fd) {
        cand.has_sdf = 1;
        phb_parse_flow_description(pdr->pdi.sdfFilter.flowDescription, &cand);
    }

    if (is_uplink) {
        /* UL: hash by TEID */
        if (cand.teid == 0) return -1;   /* no TEID — can't hash */
        return phb_insert_candidate(t->teid_tbl, PHB_TEID_BUCKETS,
                                    cand.teid, &cand);
    } else {
        /* DL: hash by UE IP */
        if (cand.ue_ip == 0) return -1;  /* no UE IP — can't hash */
        return phb_insert_candidate(t->ueip_tbl, PHB_UEIP_BUCKETS,
                                    cand.ue_ip, &cand);
    }
}


/* ══════════════════════════════════════════════════════════════════════
 *  Lookup API (UPF-U side — called per-packet from packet_handler)
 * ══════════════════════════════════════════════════════════════════════ */

/* Find the bucket for a given key. Returns NULL on miss. */
static inline const phb_bucket_t *
phb_find_bucket(const phb_bucket_t *tbl, uint32_t n_buckets, uint32_t key)
{
    uint32_t idx = phb_hash32(key, n_buckets);
    uint32_t start = idx;

    for (;;) {
        const phb_bucket_t *b = &tbl[idx];
        if (b->count == 0)
            return NULL;           /* empty slot → key not in table */
        if (b->key == key)
            return b->overflow
                ? NULL             /* poisoned: incomplete candidates,
                                   * must fall back to full classifier */
                : b;              /* found — safe to use */

        idx = (idx + 1) % n_buckets;
        if (idx == start)
            return NULL;           /* wrapped around — not found */
    }
}

/* Prefix-match helper: both ip and cand_ip are in host byte order. */
static inline bool
phb_prefix_match(uint32_t pkt_ip, uint32_t cand_ip, uint8_t pref)
{
    if (pref == 0)  return true;           /* wildcard — matches all   */
    if (pref >= 32) return pkt_ip == cand_ip; /* exact host — fast path */
    uint32_t mask = 0xFFFFFFFFu << (32 - pref);
    return (pkt_ip & mask) == (cand_ip & mask);
}

/* Check if a candidate's SDF filter matches the packet.
 * If has_sdf==0, this is a catch-all (matches everything).
 * All IPs and ports are in host byte order (same as ps_packet_t). */
static inline bool
phb_match_sdf(const phb_candidate_t *c, const ps_packet_t *pkt)
{
    /* No SDF filter → wildcard match (catch-all PDR) */
    if (!c->has_sdf)
        return true;

    /* QFI (0 = wildcard) */
    if (c->qfi != 0 && pkt->qfi != c->qfi)
        return false;

    /* Protocol (0 = wildcard, i.e. "ip" in the flow description) */
    if (c->sdf_proto != 0 && pkt->proto != c->sdf_proto)
        return false;

    /* Source IP prefix */
    if (!phb_prefix_match(pkt->src_ip, c->sdf_src_ip, c->sdf_src_pref))
        return false;

    /* Destination IP prefix */
    if (!phb_prefix_match(pkt->dst_ip, c->sdf_dst_ip, c->sdf_dst_pref))
        return false;

    /* Source port (0 = wildcard) */
    if (c->sdf_src_port != 0 && pkt->src_port != c->sdf_src_port)
        return false;

    /* Destination port (0 = wildcard) */
    if (c->sdf_dst_port != 0 && pkt->dst_port != c->sdf_dst_port)
        return false;

    return true;
}

/* Classify a packet using the hash bypass table.
 * Returns the matching UPDK_PDR*, or NULL on miss (caller should
 * fall back to PartitionSort).
 *
 * For UL: key = TEID, also checks QFI
 * For DL: key = UE IP (host byte order), checks SDF
 */
static inline const UPDK_PDR *
phb_classify_ul(const phb_table_t *t, uint32_t teid,
                const ps_packet_t *pkt)
{
    const phb_bucket_t *b = phb_find_bucket(t->teid_tbl,
                                            PHB_TEID_BUCKETS, teid);
    if (!b) return NULL;

    /* Scan candidates in precedence order (already sorted).
     * First match wins (lowest precedence value = highest priority). */
    for (int i = 0; i < b->count; i++) {
        const phb_candidate_t *c = &b->cands[i];
        /* QFI check */
        if (c->qfi != 0 && pkt->qfi != c->qfi)
            continue;
        if (phb_match_sdf(c, pkt))
            return c->pdr;
    }
    return NULL;   /* no match in candidates — fall back */
}

static inline const UPDK_PDR *
phb_classify_dl(const phb_table_t *t, uint32_t ue_ip_host,
                const ps_packet_t *pkt)
{
    const phb_bucket_t *b = phb_find_bucket(t->ueip_tbl,
                                            PHB_UEIP_BUCKETS, ue_ip_host);
    if (!b) return NULL;

    for (int i = 0; i < b->count; i++) {
        const phb_candidate_t *c = &b->cands[i];
        if (phb_match_sdf(c, pkt))
            return c->pdr;
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif