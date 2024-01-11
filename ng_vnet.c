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

#include <netgraph/ng_message.h>
#include "ng_vnet.h"
#include "util.h"
#include <netgraph/netgraph.h>

#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_VNET, "netgraph_vnet", "netgraph vnet node");
#else
#	define M_NETGRAPH_VNET M_NETGRAPH
#endif

struct ng_vnet_private
{
	struct dlist list;
	node_p       node;
};
typedef struct ng_vnet_private *priv_p;

static ng_constructor_t ng_vnet_constructor;
static ng_rcvmsg_t      ng_vnet_rcvmsg;
static ng_shutdown_t    ng_vnet_shutdown;
static ng_rcvdata_t     ng_vnet_rcvdata;

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_vnet_cmdlist[] = {
	{ NGM_VNET_COOKIE, NGM_VNET_CONNECT, "connect", NULL, NULL },
	{ 0 }
};

static struct ng_type ng_vnet_typestruct = {
	.version     = NG_ABI_VERSION,
	.name        = NG_VNET_NODE_TYPE,
	.constructor = ng_vnet_constructor,
	.rcvmsg      = ng_vnet_rcvmsg,
	.shutdown    = ng_vnet_shutdown,
	.rcvdata     = ng_vnet_rcvdata,
	.cmdlist     = ng_vnet_cmdlist,
};
NETGRAPH_INIT(vnet, &ng_vnet_typestruct);

static int
ng_vnet_constructor(node_p node)
{
	priv_p priv = malloc(sizeof(*priv), M_NETGRAPH_VNET, M_WAITOK);
	NG_NODE_SET_PRIVATE(node, priv);
	dlist_init(&priv->list);
	return 0;
}

static int
ng_vnet_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const priv_p    priv  = NG_NODE_PRIVATE(node);
	int             error = 0;
	struct ng_mesg *msg;
	(void)priv;

	NGI_GET_MSG(item, msg);
	switch(msg->header.typecookie)
	{
		case NGM_VNET_COOKIE:
			switch(msg->header.cmd)
			{
				case NGM_VNET_CONNECT:
				{
					/* TODO:
					 * 1. Get JID.
					 * 2. Find child jail with JID.
					 * 3. Create ng_vnet node in that jail.
					 * 4. Get its priv structure.
					 * 5. Insert it into our list.
					 */
					uprintf("connect!\n");
					break;
				}
			}
			break;
		default: error = EINVAL; break;
	}
	NG_FREE_MSG(msg);
	return error;
}

static int
ng_vnet_rcvdata(hook_p hook, item_p item)
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
		struct ng_vnet_private *I =
		  containerof(i, struct ng_vnet_private, list);
		node2 = I->node;
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
ng_vnet_shutdown(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	dlist_remove(&priv->list);
	free(priv, M_NETGRAPH_VNET);
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	return 0;
}
