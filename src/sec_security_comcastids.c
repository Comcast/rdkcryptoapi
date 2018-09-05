/*
 * ============================================================================
 * COMCAST CONFIDENTIAL AND PROPRIETARY
 * ============================================================================
 * This file and its contents are the intellectual property of Comcast.  It may
 * not be used, copied, distributed or otherwise  disclosed in whole or in part
 * without the express written permission of Comcast.
 * ============================================================================
 * Copyright (c) 2013, 2014 Comcast. All rights reserved.
 * ============================================================================
 */

#include "sec_security_comcastids.h"
#include "sec_security.h"
#include <string.h>

typedef struct
{
    SEC_OBJECTID object_id;
    const char* urn;
} Sec_ObjUrn;

static Sec_ObjUrn g_sec_obj_urns[] = {
    { SEC_OBJECTID_COMCAST_SGNCERT, "comcast:xcal:sgnCert" },
    { SEC_OBJECTID_COMCAST_SGNSUBCACERT, "comcast:xcal:sgnSubCaCert" },
    { SEC_OBJECTID_COMCAST_SGNROOTCACERT, "comcast:xcal:sgnRootCaCert"},
    { SEC_OBJECTID_COMCAST_ENCCERT, "comcast:xcal:encCert" },
    { SEC_OBJECTID_COMCAST_ENCSUBCACERT, "comcast:xcal:encSubCaCert"},
    { SEC_OBJECTID_COMCAST_ENCROOTCACERT, "comcast:xcal:encRootCaCert"},
    { SEC_OBJECTID_COMCAST_TLSCERT, "comcast:xcal:tlsCert"},
    { SEC_OBJECTID_COMCAST_TLSSUBCACERT, "comcast:xcal:tlsCert"},
    { SEC_OBJECTID_COMCAST_TLSROOTCACERT, "comcast:xcal:tlsRootCaCert"},
    { SEC_OBJECTID_COMCAST_CERTCA01CERT, "comcast:xcal:certCa01Cert"},
    { SEC_OBJECTID_COMCAST_STATUSCA01CERT, "comcast:xcal:statusCa01Cert"},
    { SEC_OBJECTID_COMCAST_SGNKEY, "comcast:xcal:sgnKey"},
    { SEC_OBJECTID_COMCAST_ENCKEY, "comcast:xcal:encKey"},
    { SEC_OBJECTID_COMCAST_TLSKEY, "comcast:xcal:tlsKey"},
    { SEC_OBJECTID_COMCAST_PKIBUNDLE, "comcast:xcal:pkiBundle"},
    { SEC_OBJECTID_COMCAST_HASHLOCKED, "comcast:xcal:hashLock"},
    { SEC_OBJECTID_ADOBE_DRMMODELKEY, "adobe:flashAccess:drmModelKey"},
    { SEC_OBJECTID_ADOBE_DRMMODELCERT, "adobe:flashAccess:drmModelCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:drmModelIntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATECACERT, "adobe:flashAccess:drmModelIntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELROOTCACERT, "adobe:flashAccess:drmModelRootCaCert"},
    { SEC_OBJECTID_ADOBE_SD01CERT, "adobe:flashAccess:sd01Cert"},
    { SEC_OBJECTID_ADOBE_SD01INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd01IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD01INTERMEDIATECACERT, "adobe:flashAccess:sd01IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD01ROOTCACERT, "adobe:flashAccess:sd01RootCaCert"},
    { SEC_OBJECTID_ADOBE_SD02CERT, "adobe:flashAccess:sd02Cert"},
    { SEC_OBJECTID_ADOBE_SD02INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd02IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD02INTERMEDIATECACERT, "adobe:flashAccess:sd02IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD02ROOTCACERT, "adobe:flashAccess:sd02RootCaCert"},
    { SEC_OBJECTID_ADOBE_SD03CERT, "adobe:flashAccess:sd03Cert"},
    { SEC_OBJECTID_ADOBE_SD03INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd03IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD03INTERMEDIATECACERT, "adobe:flashAccess:sd03IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD03ROOTCACERT, "adobe:flashAccess:sd03RootCaCert"},
    { SEC_OBJECTID_ADOBE_INDIVTRANSPORTCERT, "adobe:flashAccess:indivTransportCert"},
    { SEC_OBJECTID_ADOBE_SD01KEY, "adobe:flashAccess:sd01Key"},
    { SEC_OBJECTID_ADOBE_SD02KEY, "adobe:flashAccess:sd02Key"},
    { SEC_OBJECTID_ADOBE_SD03KEY, "adobe:flashAccess:sd03Key"},
    { SEC_OBJECTID_ADOBE_PRODADOBEROOTDIGEST, "adobe:flashAccess:prodAdobeRootDigest"},
    { SEC_OBJECTID_ADOBE_DRMPKI, "adobe:flashAccess:drmPkiBundle" },
    { SEC_OBJECTID_INVALID, "" }
};

const char* Sec_GetObjectUrn(SEC_OBJECTID object_id)
{
    Sec_ObjUrn* ptr = &g_sec_obj_urns[0];

    while (ptr->object_id != SEC_OBJECTID_INVALID)
    {
        if (ptr->object_id == object_id)
            return ptr->urn;
    }

    return "";
}

SEC_OBJECTID Sec_GetObjectId(const char* urn)
{
    Sec_ObjUrn* ptr = &g_sec_obj_urns[0];

    while (ptr->object_id != SEC_OBJECTID_INVALID)
    {
        if (strcmp(urn, ptr->urn) == 0)
            return ptr->object_id;
    }

    return SEC_OBJECTID_INVALID;
}

