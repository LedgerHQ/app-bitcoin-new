#include "btchip_display_variables.h"

#ifdef TARGET_NANOS
union display_variables __attribute__ ((section (".legacy_globals"))) vars;
#else
union display_variables vars;
#endif
