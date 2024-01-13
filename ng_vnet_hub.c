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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/jail.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <net/vnet.h>
#include "ng_vnet_hub.h"
#include "util.h"
#include <netgraph/netgraph.h>

#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_VNET_HUB,
                     "netgraph_vnet_hub",
                     "netgraph vnet hub node");
#else
#	define M_NETGRAPH_VNET M_NETGRAPH
#endif

#define ERROUT(x)    \
	{                \
		error = (x); \
		goto done;   \
	}

struct private
{
	struct dlist list;
	node_p       node;
};
typedef struct private *priv_p;

static ng_constructor_t constructor;
static ng_rcvmsg_t      rcvmsg;
static ng_shutdown_t    shutdown;
static ng_rcvdata_t     rcvdata;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist cmdlist[] = {
	{ NGM_VNET_HUB_COOKIE,
     NGM_VNET_HUB_CONNECT, "connect",
     &ng_parse_int32_type,
     NULL },
	{ 0 }
};

static struct ng_type typestruct = {
	.version     = NG_ABI_VERSION,
	.name        = NG_VNET_HUB_NODE_TYPE,
	.constructor = constructor,
	.rcvmsg      = rcvmsg,
	.shutdown    = shutdown,
	.rcvdata     = rcvdata,
	.cmdlist     = cmdlist,
};
NETGRAPH_INIT(vnet, &typestruct);

static int
constructor(node_p node)
{
	priv_p priv = malloc(sizeof(*priv), M_NETGRAPH_VNET_HUB, M_WAITOK);
	NG_NODE_SET_PRIVATE(node, priv);
	dlist_init(&priv->list);
	priv->node = node;
	return 0;
}

static struct prison *
vnet_to_prison(struct vnet *vnet)
{
	// TODO: Find a better way to do this
	if(vnet == vnet0) return &prison0;
	struct prison *result;
	int            descend;
	FOREACH_PRISON_DESCENDANT(&prison0, result, descend)
	{
		if(result->pr_vnet == vnet) return result;
	}
	return NULL;
}

static int
rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p    priv  = NG_NODE_PRIVATE(node);
	int             error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	switch(msg->header.typecookie)
	{
		case NGM_VNET_HUB_COOKIE:
			switch(msg->header.cmd)
			{
				case NGM_VNET_HUB_CONNECT:
				{
					if(msg->header.arglen != sizeof(uint32_t)) ERROUT(EINVAL);
					// find child jail
					int32_t        jid        = *(int32_t *)msg->data;
					struct prison *jail       = vnet_to_prison(node->nd_vnet);
					struct prison *child_jail = prison_find_child(jail, jid);
					if(child_jail == NULL) ERROUT(EINVAL);
					if(child_jail->pr_vnet == node->nd_vnet) ERROUT(EINVAL);
					CURVNET_SET(child_jail->pr_vnet);
					// create ng_vnet node inside
					node_p child_node;
					error = ng_make_node_common(&typestruct, &child_node);
					if(error != 0)
					{
						CURVNET_RESTORE();
						ERROUT(error);
					}
					error = constructor(child_node);
					if(error != 0)
					{
						NG_NODE_UNREF(child_node);
						CURVNET_RESTORE();
						ERROUT(error);
					}
					// link to it
					priv_p child_priv = NG_NODE_PRIVATE(child_node);
					dlist_insert_last(&priv->list, &child_priv->list);
					CURVNET_RESTORE();
					break;
				}
			}
			break;
		default: ERROUT(EINVAL);
	}

done:
	NG_FREE_MSG(msg);
	return error;
}

static int
rcvdata(hook_p hook, item_p item)
{
	const node_p       node = NG_HOOK_NODE(hook);
	node_p             node2;
	const priv_p       priv = NG_NODE_PRIVATE(node);
	struct mbuf *const m    = NGI_M(item);
	struct mbuf       *m2;
	hook_p             hook2;
	int                error = 0;

	/* send to other vnet nodes' hooks */
	for(struct dlist *i = priv->list.next; i != &priv->list; i = i->next)
	{
		struct private *I = containerof(i, struct private, list);
		node2             = I->node;
		LIST_FOREACH(hook2, &node2->nd_hooks, hk_hooks)
		{
			if((m2 = m_dup(m, M_NOWAIT)) == NULL)
			{
				NG_FREE_ITEM(item);
				return (ENOBUFS);
			}
			NG_SEND_DATA_ONLY(error, hook2, m2);
			if(error) continue; /* don't give up */
		}
	}

	/* send to other hooks */
	int nhooks = NG_NODE_NUMHOOKS(node);
	if(nhooks == 1)
	{
		NG_FREE_ITEM(item);
		return error;
	}
	LIST_FOREACH(hook2, &node->nd_hooks, hk_hooks)
	{
		if(hook2 == hook) continue;
		if(--nhooks == 1) NG_FWD_ITEM_HOOK(error, item, hook2);
		else
		{
			if((m2 = m_dup(m, M_NOWAIT)) == NULL)
			{
				NG_FREE_ITEM(item);
				return (ENOBUFS);
			}
			NG_SEND_DATA_ONLY(error, hook2, m2);
			if(error) continue; /* don't give up */
		}
	}
	return error;
}

static int
shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	dlist_remove(&priv->list);
	free(priv, M_NETGRAPH_VNET_HUB);
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	return 0;
}
