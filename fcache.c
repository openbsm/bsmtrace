/*-
 * Copyright (c) 2007 Aaron L. Meihm
 * Copyright (c) 2007 Christian S.J. Peron
 * All rights reserved.
 *
 * $Id$
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
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
#include "includes.h"

static int      fcache_cmp(struct fcache *, struct fcache *);

RB_PROTOTYPE(btree, fcache, f_glue, fcache_cmp);
RB_GENERATE(btree, fcache, f_glue, fcache_cmp);
TAILQ_HEAD(tailhead, dev_list) cache_head = TAILQ_HEAD_INITIALIZER(cache_head);

static int
fcache_cmp(struct fcache *fc1, struct fcache *fc2)
{

	if (fc1->f_inode > fc2->f_inode)
		return (1);
	if (fc1->f_inode < fc2->f_inode)
		return (-1);
	return (0);
}

void
fcache_destroy(void)
{
	struct fcache *fcp, *next_fcp;
	struct dev_list *dp, *dp2;

	TAILQ_FOREACH_SAFE(dp, &cache_head, d_glue, dp2) {
		for (fcp = RB_MIN(btree, &dp->d_btree); fcp != NULL;
		    fcp = next_fcp) {
			next_fcp = RB_NEXT(btree, &dp->d_btree, fcp);
			RB_REMOVE(btree, &dp->d_btree, fcp);
			free(fcp);
		}
		TAILQ_REMOVE(&cache_head, dp, d_glue);
		free(dp);
	}
}

void
fcache_init(void)
{

	TAILQ_INIT(&cache_head);
}

static struct dev_list *
fcache_locate(dev_t device)
{
	struct dev_list *dp;

	TAILQ_FOREACH(dp, &cache_head, d_glue)
		if (dp->d_device == device)
			return (dp);
	dp = malloc(sizeof(*dp));
	if (dp == NULL)
		return (NULL);
	dp->d_device = device;
	RB_INIT(&dp->d_btree);
	TAILQ_INSERT_HEAD(&cache_head, dp, d_glue);
	return (dp);
}

char *
fcache_search(dev_t device, ino_t inode)
{
	struct fcache fc, *fcp;
	struct dev_list *dp;

	dp = fcache_locate(device);
	if (dp == NULL)
		return (NULL);
	fc.f_inode = inode;
	fcp = RB_FIND(btree, &dp->d_btree, &fc);
	if (fcp == NULL)
		return (NULL);
	return (fcp->f_pathname);
}

void
fcache_add_entry(dev_t device, ino_t inode, char *pathname)
{
	struct dev_list *dp;
	struct fcache *fcp;
	char *ret;

	ret = fcache_search(device, inode);
	if (ret != NULL)
		return;
	dp = fcache_locate(device);
	if (dp == NULL) {
		(void) fprintf(stderr, "failed to allocate cache\n");
		return;
	}
	fcp = malloc(sizeof(*fcp));
	if (fcp == NULL) {
		(void) fprintf(stderr, "failed to allocate cache object\n");
		return;
	}
	fcp->f_inode = inode;
	fcp->f_pathname = strdup(pathname);
	if (RB_INSERT(btree, &dp->d_btree, fcp) != 0) {
		free(fcp);
		printf("item already existed\n");
	}
}

