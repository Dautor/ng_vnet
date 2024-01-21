/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Karlo Miličević
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETGRAPH_NG_VNET_HUB_H_
#define _NETGRAPH_NG_VNET_HUB_H_

/* Node type name and magic cookie. */
#define NG_VNET_HUB_NODE_TYPE "vnet_hub"
#define NGM_VNET_HUB_COOKIE   3548444763

struct ngm_vnet_hub_list_node
{
	uint32_t nodeAddress;
	int32_t  jid;
};
#define NGM_VNET_HUB_LIST_NODE_FIELDS {       \
    { "nodeAddress", &ng_parse_uint32_type }, \
    { "jid",         &ng_parse_int32_type },  \
    { NULL }                                  \
}

struct ngm_vnet_hub_list
{
	uint32_t                      n;
	struct ngm_vnet_hub_list_node nodes[];
};
#define NGM_VNET_HUB_LIST_FIELDS {             \
    { "n",     &ng_parse_uint32_type },        \
    { "nodes", &ng_parse_vnet_hub_list_type }, \
    { NULL }                                   \
}


/* Netgraph control messages */
enum
{
	NGM_VNET_HUB_CONNECT = 1,
	NGM_VNET_HUB_LIST,
};

#endif /* _NETGRAPH_NG_VNET_HUB_H_ */
