#define _XOPEN_SOURCE
#include <time.h>

/* put in a file by itself so _XOPEN_SOURCE does not mess with outside compile */

char * SecUtils_strptime(const char *iso_time, const char* format, struct tm *tm)
{
    return strptime(iso_time, format, tm);
}

