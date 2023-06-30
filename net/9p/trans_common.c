// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright IBM Corporation, 2010
 * Author Venkateswararao Jujjuri <jvrao@linux.vnet.ibm.com>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include "trans_common.h"

/**
 * p9_unpin_pages - Unpin pages after the transaction.
 * @pages: array of pages to be put
 * @nr_pages: size of array
 */
void p9_unpin_pages(struct page **pages, int nr_pages)
{
	int i;

	for (i = 0; i < nr_pages; i++)
		if (pages[i])
			unpin_user_page(pages[i]);
}
EXPORT_SYMBOL(p9_unpin_pages);
