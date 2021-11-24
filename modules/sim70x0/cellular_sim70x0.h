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

#ifndef __CELLULAR_SIM70x0_H__
#define __CELLULAR_SIM70x0_H__

/* *INDENT-OFF* */
#ifdef __cplusplus
    extern "C" {
#endif
/* *INDENT-ON* */

/* AT Command timeout for PDN activation */
#define PDN_ACTIVATION_PACKET_REQ_TIMEOUT_MS       ( 150000UL )

/* AT Command timeout for PDN deactivation. */
#define PDN_DEACTIVATION_PACKET_REQ_TIMEOUT_MS     ( 40000UL )

/* AT Command timeout for Socket connection */
#define SOCKET_CONNECT_PACKET_REQ_TIMEOUT_MS       ( 150000UL )

#define PACKET_REQ_TIMEOUT_MS                      ( 5000UL )

/* AT Command timeout for Socket disconnection */
#define SOCKET_DISCONNECT_PACKET_REQ_TIMEOUT_MS    ( 12000UL )

#define DATA_SEND_TIMEOUT_MS                       ( 50000UL )
#define DATA_READ_TIMEOUT_MS                       ( 50000UL )

#define cid2pdn( cid )      (cid+1)         //0-4
#define pdn2cid( pdn )      (pdn-1)         //1-16

/**
 * @brief DNS query result.
 */
typedef enum cellularDnsQueryResult
{
    CELLULAR_DNS_QUERY_SUCCESS,
    CELLULAR_DNS_QUERY_FAILED,
    CELLULAR_DNS_QUERY_MAX,
    CELLULAR_DNS_QUERY_UNKNOWN
} cellularDnsQueryResult_t;

typedef enum cellularEventBitEnum
{
    EVENT_BIT_PDN_ACT = (1 << 0),
    EVENT_BIT_RX_DATA = (1 << 1),
}   cellularEventBit_t;

typedef struct cellularModuleContext cellularModuleContext_t;

/**
 * @brief DNS query URC callback fucntion.
 */
typedef void (*CellularDnsResultEventCallback_t)(cellularModuleContext_t* pModuleContext,
    char* pDnsResult,
    char* pDnsUsrData);

struct cellularModuleContext
{
    /* DNS related variables. */
    PlatformMutex_t dnsQueryMutex; /* DNS query mutex to protect the following data. */
    QueueHandle_t pktDnsQueue;     /* DNS queue to receive the DNS query result. */
    uint8_t dnsResultNumber;       /* DNS query result number. */
    uint8_t dnsIndex;              /* DNS query current index. */
    char * pDnsUsrData;            /* DNS user data to store the result. */
    CellularDnsResultEventCallback_t dnsEventCallback;

    const CellularPdnConfig_t*  pPdnCfg;
    EventGroupHandle_t          pdnEvent;   /* for AT+CNACT wait +APP PDP: response     */
};


CellularPktStatus_t _Cellular_ParseSimstat( char * pInputStr,
                                            CellularSimCardState_t * pSimState );

extern CellularAtParseTokenMap_t CellularUrcHandlerTable[];
extern uint32_t CellularUrcHandlerTableSize;

extern const char * CellularSrcTokenErrorTable[];
extern uint32_t CellularSrcTokenErrorTableSize;

extern const char * CellularSrcTokenSuccessTable[];
extern uint32_t CellularSrcTokenSuccessTableSize;

extern const char * CellularUrcTokenWoPrefixTable[];
extern uint32_t CellularUrcTokenWoPrefixTableSize;

extern BOOL    IsValidCID(int cid);
extern BOOL    IsValidSockID(int sid);

/* *INDENT-OFF* */
#ifdef __cplusplus
    }
#endif
/* *INDENT-ON* */

#endif /* ifndef __CELLULAR_SIM70x0_H__ */
