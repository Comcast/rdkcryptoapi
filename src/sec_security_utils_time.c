#include "sec_security_utils.h"
#include <string.h>
#include <time.h>

#define SEC_ISO_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

char * SecUtils_strptime(const char *, const char*, struct tm *);

SEC_SIZE SecUtils_GetUtcNow()
{
    time_t now = time(NULL);
    return (SEC_SIZE)now;
}

char * SecUtils_Epoch2IsoTime(SEC_SIZE epoch, char* iso_time, SEC_SIZE iso_time_size)
{
    time_t in_time = (time_t)epoch;
    struct tm ts = {0};
    memset(iso_time, 0, iso_time_size);
    if ( 0== strftime(iso_time, iso_time_size, SEC_ISO_TIME_FORMAT "Z", gmtime_r(&in_time, &ts)))
    {
        memset(iso_time, 0, iso_time_size);
    }
    return iso_time;
}

SEC_SIZE SecUtils_IsoTime2Epoch(const char* iso_time, SEC_SIZE *epoch)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    struct tm _tm = {0};
    char *strptimeResult = NULL;
    char *tz = getenv("TZ");

    if (tz)
        tz=strdup(tz);
    setenv("TZ","",1);
    tzset();

    *epoch = SEC_INVALID_EPOCH;

    strptimeResult = SecUtils_strptime(iso_time, SEC_ISO_TIME_FORMAT ,&_tm);
    if (NULL == strptimeResult || *strptimeResult != 'Z')
    {
        SEC_LOG_ERROR("parse error for iso time '%s'", iso_time);
        goto done;
    }
    *epoch = (SEC_SIZE) (mktime(&_tm));

    status = SEC_RESULT_SUCCESS;

    done:

    if(tz)
    {
        setenv("TZ", tz, 1);
        free(tz);
    }

    return *epoch;
}
