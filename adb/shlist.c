/*-------------------------------------------------------------------*/
/*                         List  Functionality                       */
/*-------------------------------------------------------------------*/
/* #define SH_LIST_DEBUG */
/*-------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include "shlist.h"
/*-------------------------------------------------------------------*/
void shListInitList( SHLIST *listPtr )
{
  listPtr->data = (void *)0L;
  listPtr->next = listPtr;
  listPtr->prev = listPtr;
}

SHLIST *shListFindItem( SHLIST *head, void *val, shListEqual func )
{
  SHLIST *item;

  for(item=head->next;( item != head );item=item->next)
    if( func ) {
      if( func( val, item->data ) ) {
        return( item );
      }
    }
    else {
      if( item->data == val ) {
        return( item );
      }
    }
  return( NULL );
}

SHLIST *shListGetLastItem( SHLIST *head )
{
  if( head->prev != head )
    return( head->prev );
  return( NULL );
}

SHLIST *shListGetFirstItem( SHLIST *head )
{
  if( head->next != head )
    return( head->next );
  return( NULL );
}

SHLIST *shListGetNItem( SHLIST *head, unsigned long num )
{
  SHLIST *item;
  unsigned long i;

  for(i=0,item=head->next;( (i < num) && (item != head) );i++,item=item->next);
  if( item != head )
    return( item );
  return( NULL );
}

SHLIST *shListGetNextItem( SHLIST *head, SHLIST *item )
{
  if( item == NULL )
    return( NULL );
  if( item->next != head )
    return( item->next );
  return( NULL );
}

SHLIST *shListGetPrevItem( SHLIST *head, SHLIST *item )
{
  if( item == NULL )
    return( NULL );
  if( item->prev != head )
    return( item->prev );
  return( NULL );
}

void shListDelItem( SHLIST *head, SHLIST *item, shListFree func )
{
  if( item == NULL )
    return;
#ifdef SH_LIST_DEBUG
  fprintf(stderr, "Del %lx\n", (unsigned long)(item->data));
#endif
  (item->prev)->next = item->next;
  (item->next)->prev = item->prev;
  if( func && item->data ) {
    func( (void *)(item->data) );
  }
  free( item );
  head->data = (void *)((unsigned long)(head->data) - 1);
}

void shListInsFirstItem( SHLIST *head, void *val )
{ /* Insert to the beginning of the list */
  SHLIST *item;

  item = (SHLIST *)malloc( sizeof(SHLIST) );
  if( item == NULL )
    return;
  item->data = val;
  item->next = head->next;
  item->prev = head;
  (head->next)->prev = item;
  head->next = item;
#ifdef SH_LIST_DEBUG
  fprintf(stderr, "Ins First %lx\n", (unsigned long)(item->data));
#endif
  head->data = (void *)((unsigned long)(head->data) + 1);
}

void shListInsLastItem( SHLIST *head, void *val )
{ /* Insert to the end of the list */
  SHLIST *item;

  item = (SHLIST *)malloc( sizeof(SHLIST) );
  if( item == NULL )
    return;
  item->data = val;
  item->next = head;
  item->prev = head->prev;
  (head->prev)->next = item;
  head->prev = item;
#ifdef SH_LIST_DEBUG
  fprintf(stderr, "Ins Last %lx\n", (unsigned long)(item->data));
#endif
  head->data = (void *)((unsigned long)(head->data) + 1);
}

void shListInsBeforeItem( SHLIST *head, void *val, void *etal, 
                          shListCmp func )
{
  SHLIST *item, *iptr;

  if( func == NULL )
    shListInsFirstItem( head, val );
  else {
    item = (SHLIST *)malloc( sizeof(SHLIST) );
    if( item == NULL )
      return;
    item->data = val;
    for(iptr=head->next;( iptr != head );iptr=iptr->next)
      if( func( val, iptr->data, etal ) )
         break;
    item->next = iptr;
    item->prev = iptr->prev;
    (iptr->prev)->next = item;
    iptr->prev = item;
#ifdef SH_LIST_DEBUG
    fprintf(stderr, "Ins Before %lx\n", (unsigned long)(item->data));
#endif
    head->data = (void *)((unsigned long)(head->data) + 1);
  }
}

void shListDelAllItems( SHLIST *head, shListFree func )
{
  SHLIST *item;

  for(item=head->next;( item != head );) {
    shListDelItem( head, item, func );
    item = head->next;
  }
  head->data = (void *)0L;
}

void shListPrintAllItems( SHLIST *head, shListPrint func )
{
#ifdef SH_LIST_DEBUG
  SHLIST *item;

  for(item=head->next;( item != head );item=item->next)
    if( func ) {
      func(item->data);
    }
    else {
      fprintf(stderr, "Item: %lx\n",(unsigned long)(item->data));
    }
#endif
}

unsigned long shListGetCount( SHLIST *head )
{
  return( (unsigned long)(head->data) );
}
