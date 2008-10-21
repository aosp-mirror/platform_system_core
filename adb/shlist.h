/*-------------------------------------------------------------------*/
/*                         List  Functionality                       */
/*-------------------------------------------------------------------*/
#ifndef _SHLIST_H_
#define _SHLIST_H_

typedef struct SHLIST_STRUC {
  void *data;
  struct SHLIST_STRUC *next;
  struct SHLIST_STRUC *prev;
} SHLIST;

typedef int (*shListCmp)( void *valo, void *valn, void *etalon );
typedef int (*shListPrint)( void *val );
typedef void (*shListFree)( void *val );
typedef int (*shListEqual)( void *val,  void *idata );

void shListInitList( SHLIST *listPtr );
SHLIST *shListFindItem( SHLIST *head, void *val, shListEqual func );
SHLIST *shListGetFirstItem( SHLIST *head );
SHLIST *shListGetNItem( SHLIST *head, unsigned long num );
SHLIST *shListGetLastItem( SHLIST *head );
SHLIST *shListGetNextItem( SHLIST *head, SHLIST *item );
SHLIST *shListGetPrevItem( SHLIST *head, SHLIST *item );
void shListDelItem( SHLIST *head, SHLIST *item, shListFree func );
void shListInsFirstItem( SHLIST *head, void *val );
void shListInsBeforeItem( SHLIST *head, void *val, void *etalon, 
                          shListCmp func );
void shListInsLastItem( SHLIST *head, void *val );
void shListDelAllItems( SHLIST *head, shListFree func );
void shListPrintAllItems( SHLIST *head, shListPrint func );
unsigned long shListGetCount( SHLIST *head );

#endif
