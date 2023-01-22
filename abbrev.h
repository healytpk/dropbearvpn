#ifndef H__ABBREV
#define H__ABBREV

#define ALEN(a)  (sizeof(a) / sizeof(*(a)))
#define PEND(a)  (  (a) + ALEN((a))  )
#define PLAST(a) (  PEND((a)) - 1  )

#ifndef NO_ERRPRINT
    #define ErrPrint(...) /* Maybe put a message box call here */
#else
    #define ErrPrint(...) /* Nothing */
#endif


#endif
