#pragma once

#include <sys/param.h>

#define containerof(x, type, member) (type *)(void *)((uint8_t *)(x)-__builtin_offsetof(type, member))

struct dlist
{
	struct dlist *_Nonnull next;
	struct dlist *_Nonnull prev;
};

inline void
dlist_init(struct dlist *_Nonnull list)
{
	list->next = list;
	list->prev = list;
}

inline bool
dlist_empty(struct dlist *_Nonnull list)
{
	return list->next == list;
}

inline size_t
dlist_size(struct dlist *_Nonnull list)
{
	size_t i = 0;
	for(struct dlist *I = list->next; I != list; I = I->next) ++i;
	return i;
}

inline void
dlist_insert_first(struct dlist *_Nonnull list,
                   struct dlist *_Nonnull element)
{
	element->prev       = list;
	element->next       = list->next;
	element->next->prev = element;
	element->prev->next = element;
}

inline void
dlist_insert_last(struct dlist *_Nonnull list,
                  struct dlist *_Nonnull element)
{
	element->next       = list;
	element->prev       = list->prev;
	element->next->prev = element;
	element->prev->next = element;
}

inline void
dlist_remove(struct dlist *_Nonnull element)
{
	element->prev->next = element->next;
	element->next->prev = element->prev;
}
