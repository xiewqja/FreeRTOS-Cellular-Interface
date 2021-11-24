/*
 * FreeRTOS-Cellular-Interface v1.1.0
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 */

/* The config header is always included first. */


#include <stdint.h>
#include "cellular_platform.h"
#include "cellular_config.h"
#include "cellular_config_defaults.h"
#include "cellular_common.h"
#include "cellular_common_portable.h"
#include "cellular_sim70x0.h"

/*-----------------------------------------------------------*/

#define ENBABLE_MODULE_UE_RETRY_COUNT      ( 3U )
#define ENBABLE_MODULE_UE_RETRY_TIMEOUT    ( 5000U )

/*-----------------------------------------------------------*/

static CellularError_t sendAtCommandWithRetryTimeout( CellularContext_t * pContext,
                                                      const CellularAtReq_t * pAtReq );

/*-----------------------------------------------------------*/

static cellularModuleContext_t cellularSim70x0Context;

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
const char * CellularSrcTokenErrorTable[] =
{ "ERROR", "BUSY", "NO CARRIER", "NO ANSWER", "NO DIALTONE", "ABORTED", "+CMS ERROR", "+CME ERROR", "SEND FAIL" };
/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
uint32_t CellularSrcTokenErrorTableSize = sizeof( CellularSrcTokenErrorTable ) / sizeof( char * );

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
const char * CellularSrcTokenSuccessTable[] =
{ "OK", "CONNECT", "SEND OK", ">" };
/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
uint32_t CellularSrcTokenSuccessTableSize = sizeof( CellularSrcTokenSuccessTable ) / sizeof( char * );

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
const char * CellularUrcTokenWoPrefixTable[] =
{ "NORMAL POWER DOWN", "PSM POWER DOWN", "RDY"};
/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
uint32_t CellularUrcTokenWoPrefixTableSize = sizeof( CellularUrcTokenWoPrefixTable ) / sizeof( char * );

/*-----------------------------------------------------------*/

static CellularError_t sendAtCommandWithRetryTimeout( CellularContext_t * pContext,
                                                      const CellularAtReq_t * pAtReq )
{
    CellularError_t cellularStatus = CELLULAR_SUCCESS;
    CellularPktStatus_t pktStatus = CELLULAR_PKT_STATUS_OK;
    uint8_t tryCount = 0;

    if( pAtReq == NULL )
    {
        cellularStatus = CELLULAR_BAD_PARAMETER;
    }
    else
    {
        for( ; tryCount < ENBABLE_MODULE_UE_RETRY_COUNT; tryCount++ )
        {
            pktStatus = _Cellular_TimeoutAtcmdRequestWithCallback( pContext, *pAtReq, ENBABLE_MODULE_UE_RETRY_TIMEOUT );
            cellularStatus = _Cellular_TranslatePktStatus( pktStatus );

            if( cellularStatus == CELLULAR_SUCCESS )
            {
                break;
            }
        }
    }

    return cellularStatus;
}

/*-----------------------------------------------------------*/

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
CellularError_t Cellular_ModuleInit( const CellularContext_t * pContext,
                                     void ** ppModuleContext )
{
    CellularError_t cellularStatus = CELLULAR_SUCCESS;
    bool status = false;

    if( pContext == NULL )
    {
        cellularStatus = CELLULAR_INVALID_HANDLE;
    }
    else if( ppModuleContext == NULL )
    {
        cellularStatus = CELLULAR_BAD_PARAMETER;
    }
    else
    {
        /* Initialize the module context. */
        ( void ) memset( &cellularSim70x0Context, 0, sizeof( cellularModuleContext_t ) );

        /* Create the mutex for DNS. */
        status = PlatformMutex_Create( &cellularSim70x0Context.dnsQueryMutex, false );

        if( status == false )
        {
            cellularStatus = CELLULAR_NO_MEMORY;
        }
        else
        {
            /* Create the queue for DNS. */
            cellularSim70x0Context.pktDnsQueue = xQueueCreate( 1, sizeof( cellularDnsQueryResult_t ) );

            if(cellularSim70x0Context.pktDnsQueue == NULL )
            {
                PlatformMutex_Destroy( &cellularSim70x0Context.dnsQueryMutex );
                cellularStatus = CELLULAR_NO_MEMORY;
            }
            else
            {
                *ppModuleContext = ( void * )&cellularSim70x0Context;
                cellularSim70x0Context.pdnEvent = xEventGroupCreate();
            }
        }
    }

    return cellularStatus;
}

/*-----------------------------------------------------------*/

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
CellularError_t Cellular_ModuleCleanUp( const CellularContext_t * pContext )
{
    CellularError_t cellularStatus = CELLULAR_SUCCESS;

    if( pContext == NULL )
    {
        cellularStatus = CELLULAR_INVALID_HANDLE;
    }
    else
    {
        /* Delete DNS queue. */
        vQueueDelete(cellularSim70x0Context.pktDnsQueue );

        /* Delete the mutex for DNS. */
        PlatformMutex_Destroy( &cellularSim70x0Context.dnsQueryMutex );
    }

    return cellularStatus;
}

static  BYTE    nSockID_Min = 0;
static  BYTE    nSockID_Max = CELLULAR_SOCKET_MAX;  /* 0-11 */

static  BYTE    nCID_Min = 1;
static  BYTE    nCID_Max = CELLULAR_CID_MAX;    /* 0-3  */

BOOL    IsValidSockID(int sid)
{
    return sid >= (int)nSockID_Min && sid <= (int)nSockID_Max;
}

BOOL    IsValidCID(int cid)
{
    return cid >= (int)nCID_Min && cid <= (int)nCID_Max;
}



static CellularPktStatus_t set_SockID_range_cb(CellularContext_t* pContext,
    const CellularATCommandResponse_t* pAtResp,
    void* pData,
    uint16_t dataLen)
{
    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(dataLen);

    if (pAtResp != NULL && pAtResp->pItm != NULL && pAtResp->pItm->pLine != NULL)
    {
        /* Handling: +CACID:(0-12)   */
        char    ns[8];
        char* pLine = pAtResp->pItm->pLine;
        char* pB1, * pE1, * pB2, * pE2;

        if ((pB1 = strchr(pLine, '(')) != NULL
            && (pE1 = strchr(pLine, '-')) != NULL
            && (pE2 = strchr(pLine, ')')) != NULL)
        {
            memset(ns, 0, sizeof(ns));
            strncpy(ns, pB1, pE1 - pB1);
            nSockID_Min = (uint8_t)atoi(ns);

            pB2 = pE1 + 1;
            memset(ns, 0, sizeof(ns));
            strncpy(ns, pB2, pE2 - pB2);
            nSockID_Max = (uint8_t)atoi(ns);

            CellularLogInfo("SockID range: %d - %d", (int)nSockID_Min, (int)nSockID_Max);
            return CELLULAR_AT_SUCCESS;
        }
    }

    return CELLULAR_AT_ERROR;
}

static CellularPktStatus_t set_CID_range_cb(CellularContext_t* pContext,
    const CellularATCommandResponse_t* pAtResp,
    void* pData,
    uint16_t dataLen)
{
    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(dataLen);

    if (pAtResp != NULL && pAtResp->pItm != NULL && pAtResp->pItm->pLine != NULL)
    {
        /*Handling: +CNACT:(0-3),(0-2)  */
        char    ns[8];
        char* pLine = pAtResp->pItm->pLine;
        char* pB1, * pE1, * pB2, * pE2;

        if ((pB1 = strchr(pLine, '(')) != NULL
            && (pE1 = strchr(pLine, '-')) != NULL
            && (pE2 = strchr(pLine, ')')) != NULL)
        {
            memset(ns, 0, sizeof(ns));
            strncpy(ns, pB1, pE1 - pB1);
            nCID_Min = (uint8_t)atoi(ns);

            pB2 = pE1 + 1;
            memset(ns, 0, sizeof(ns));
            strncpy(ns, pB2, pE2 - pB2);
            nCID_Max = (uint8_t)atoi(ns);

            CellularLogInfo("CAxxx CID range: %d - %d", nCID_Min, nCID_Max);
            return CELLULAR_AT_SUCCESS;
        }
    }

    return CELLULAR_AT_ERROR;
}


/*-----------------------------------------------------------*/

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
CellularError_t Cellular_ModuleEnableUE( CellularContext_t * pContext )
{
    CellularError_t cellularStatus = CELLULAR_SUCCESS;
    CellularAtReq_t atReqGetNoResult =
    {
        NULL,
        CELLULAR_AT_NO_RESULT,
        NULL,
        NULL,
        NULL,
        0
    };
    CellularAtReq_t atReqGetWithResult =
    {
        NULL,
        CELLULAR_AT_MULTI_WO_PREFIX,
        NULL,
        NULL,
        NULL,
        0
    };

    if( pContext != NULL )
    {
        /* Disable echo. */
        atReqGetWithResult.pAtCmd = "ATE0";
        cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetWithResult );

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            /* Disable DTR function. */
            atReqGetNoResult.pAtCmd = "AT&D0";
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            /* Enable RTS/CTS hardware flow control. */
            atReqGetNoResult.pAtCmd = "AT+IFC=2,2";
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        if (cellularStatus == CELLULAR_SUCCESS)
        {
            /* Disable DTR function. */
            atReqGetNoResult.pAtCmd = "AT+CLTS=0";  //no *PSUTTZ report
            cellularStatus = sendAtCommandWithRetryTimeout(pContext, &atReqGetNoResult);
        }

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            /* Configure Band configuration to all Cat-M1 bands. */
            atReqGetNoResult.pAtCmd = "AT+CBANDCFG=\"CAT-M\",1,3,8,18,19,26";   /*for Japan     */
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        if (cellularStatus == CELLULAR_SUCCESS)
        {
            /* Configure Band configuration to all NB-IOT bands. */
            atReqGetNoResult.pAtCmd = "AT+CBANDCFG=\"NB-IOT\",1,3,8,18,19,26";   /*for Japan    */
            cellularStatus = sendAtCommandWithRetryTimeout(pContext, &atReqGetNoResult);
        }

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            /* Configure Network mode select to Automatic. */
//          atReqGetNoResult.pAtCmd = "AT+CNMP=2";
            atReqGetNoResult.pAtCmd = "AT+CNMP=38";     /*Only LTE, no GSM support  */
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            /* Configure Network Category to be Searched under LTE RAT to LTE Cat M1 and Cat NB1. */
            switch (CELLULAR_CONFIG_DEFAULT_RAT)
            {
            case CELLULAR_RAT_CATM1:
                atReqGetNoResult.pAtCmd = "AT+CMNB=1";
                break;
            case CELLULAR_RAT_NBIOT:
                atReqGetNoResult.pAtCmd = "AT+CMNB=2";
                break;
            case CELLULAR_RAT_GSM:
                atReqGetNoResult.pAtCmd = "AT+CNMP=13";
                break;
            default:
                /* Configure RAT Searching Sequence to automatic. */
                atReqGetNoResult.pAtCmd = "AT+CMNB=3";
                break;
            }
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        if( cellularStatus == CELLULAR_SUCCESS )
        {
            atReqGetNoResult.pAtCmd = "AT+CFUN=1";
            cellularStatus = sendAtCommandWithRetryTimeout( pContext, &atReqGetNoResult );
        }

        atReqGetWithResult.pAtCmd = "AT+CACID=?";
        atReqGetWithResult.atCmdType = CELLULAR_AT_WITH_PREFIX;
        atReqGetWithResult.pAtRspPrefix = "+CACID";
        atReqGetWithResult.respCallback = set_SockID_range_cb;
        cellularStatus = _Cellular_AtcmdRequestWithCallback(pContext, atReqGetWithResult);

        atReqGetWithResult.pAtCmd = "AT+CNACT=?";
        atReqGetWithResult.atCmdType = CELLULAR_AT_WITH_PREFIX;
        atReqGetWithResult.pAtRspPrefix = "+CNACT";
        atReqGetWithResult.respCallback = set_CID_range_cb;
        cellularStatus = _Cellular_AtcmdRequestWithCallback(pContext, atReqGetWithResult);
    }

    return cellularStatus;
}

/*-----------------------------------------------------------*/

/* FreeRTOS Cellular Common Library porting interface. */
/* coverity[misra_c_2012_rule_8_7_violation] */
CellularError_t Cellular_ModuleEnableUrc( CellularContext_t * pContext )
{
    CellularError_t cellularStatus = CELLULAR_SUCCESS;
    CellularAtReq_t atReqGetNoResult =
    {
        NULL,
        CELLULAR_AT_NO_RESULT,
        NULL,
        NULL,
        NULL,
        0
    };

    atReqGetNoResult.pAtCmd = "AT+COPS=3,2";
    ( void ) _Cellular_AtcmdRequestWithCallback( pContext, atReqGetNoResult );

    atReqGetNoResult.pAtCmd = "AT+CREG=2";
    ( void ) _Cellular_AtcmdRequestWithCallback( pContext, atReqGetNoResult );

    atReqGetNoResult.pAtCmd = "AT+CGREG=2";
    ( void ) _Cellular_AtcmdRequestWithCallback( pContext, atReqGetNoResult );

    atReqGetNoResult.pAtCmd = "AT+CEREG=2";
    ( void ) _Cellular_AtcmdRequestWithCallback( pContext, atReqGetNoResult );

    atReqGetNoResult.pAtCmd = "AT+CTZR=1";
    ( void ) _Cellular_AtcmdRequestWithCallback( pContext, atReqGetNoResult );

    return cellularStatus;
}

/*-----------------------------------------------------------*/
