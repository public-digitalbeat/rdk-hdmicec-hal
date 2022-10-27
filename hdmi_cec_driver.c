
/**
 * @defgroup hdmicec
 * @{
 * @defgroup ccec
 * @{
 **********************************************************************/

#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include "ccec/drivers/hdmi_cec_driver.h"
#include "libIARM.h"
//#include "dsMgr.h"

#define DBG(fmt, args...)   fprintf(stderr, "[DSHAL_DBG] func %s line %d " fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...)   fprintf(stderr, "[DSHAL_ERR] func %s line %d " fmt, __func__, __LINE__, ##args)

typedef struct Hal_CecContext_t
{
    int cecFd;
    int logicalAddress;
    HdmiCecTxCallback_t txCB;
    void * txCBdata;
    HdmiCecRxCallback_t rxCB;
    void * rxCBdata;

} Cec_hal_Context_t;

static Cec_hal_Context_t Cec_driverCtx;
static pthread_mutex_t Cec_DriverMutex = PTHREAD_MUTEX_INITIALIZER;

static Cec_hal_Context_t *Cec_driverCtx_ptr = NULL;
static pthread_t CEC_Event_Thread;
static struct pollfd polling;
static int poll_thread_stop;

//static int cecFd;

#include "hdmi_tx_cec_20.h"

#define DEV_CEC			"/dev/cec"

static void* CEC_event_poll_fn (void *data)
{
    int timeout = 1000;
    unsigned int mask = 0;
    int read_len =0;
    int i = 0;
    unsigned char cecmsg[16] = {0};
    polling.fd= Cec_driverCtx_ptr->cecFd;
    polling.events = POLLIN;

    while (!poll_thread_stop) {
        /* this needs to be changed to infinite wait but driver while closing return frm the wait?? */	
        mask =	poll(&polling,1,timeout);

        if(mask & POLLIN || mask & POLLRDNORM )
        {
            pthread_mutex_lock(&Cec_DriverMutex);
            read_len= read(Cec_driverCtx_ptr->cecFd, &cecmsg, sizeof(cecmsg));
            if (read_len < 0) {
                ERR("read failed\n");
            } else if (Cec_driverCtx_ptr->rxCB && (read_len > 1)) {
                /* One byte reception -> PING Pkt; discard */
                printf("[HALDVR] %s: CEC message received \n",__func__);
                for(i=0; i<read_len; i++)
                    printf(" 0x%x ",cecmsg[i]);

                Cec_driverCtx_ptr->rxCB((int)Cec_driverCtx_ptr, Cec_driverCtx_ptr->rxCBdata, (unsigned char *)&cecmsg[0], read_len);
            }
            else
            {
                printf("[HALDVR] No RXcallback registered\n");
            }

            pthread_mutex_unlock(&Cec_DriverMutex);

        }

    }

}

/**
 * @brief opens an instance of CEC driver.  
 * This function should be call once before the functions in this API can be used.
 *
 * @param [in]  :  None.
 * @param [out] :  handle used by application to uniquely identify the driver instance. 
 *
 * @return Error Code:  If error code is returned, the open is failed.
 */
int HdmiCecOpen(int *handle)
{
    int ret = HDMI_CEC_IO_SUCCESS;
    
    printf("[HALDVR] %s \n",__func__);
    pthread_mutex_lock(&Cec_DriverMutex);
    if (Cec_driverCtx_ptr != NULL)
    {
        printf("[HALDVR] Cec device already opened\n");
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_SUCCESS;
    }


    Cec_driverCtx_ptr = &Cec_driverCtx;

    Cec_driverCtx_ptr->cecFd = open (DEV_CEC, O_RDWR);
    if (Cec_driverCtx_ptr->cecFd < 0)
    {
        printf ("%s CEC_device opening failed %d",DEV_CEC);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }

    int err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_OPTION_SYS_CTRL, 1);
    if (err != 0)
    {
        printf("[HALDVR] CEC_IOC_SET_OPTION_SYS_CTRL returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
#ifdef BUILD_AML_STB
    err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_DEV_TYPE, CEC_PLAYBACK_DEVICE_TYPE);
    if (err != 0) {
        printf("[HALDVR] CEC_IOC_SET_DEV_TYPE returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_ADD_LOGICAL_ADDR, CEC_PLAYBACK_DEVICE_1_ADDR);
    if (err != 0) {
        printf("[HALDVR] CEC_IOC_ADD_LOGICAL_ADDR returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_DEBUG_EN, 1);
    if (err != 0) {
        printf("[HALDVR] CEC_IOC_SET_DEBUG_EN returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_OPTION_ENALBE_CEC, 1);
    if (err != 0) {
        printf("[HALDVR] CEC_IOC_SET_OPTION_ENALBE_CEC returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
#else
    err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_ADD_LOGICAL_ADDR, 0x0);
    if (err != 0)
    {
        printf("[HALDVR] CEC_IOC_ADD_LOGICAL_ADDR returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
#endif

    poll_thread_stop=0;
    /* todo need to set the scheduling ploicy and priority */

    err = pthread_create(&CEC_Event_Thread, NULL, CEC_event_poll_fn, NULL);
    if (err)
    {
        printf("[HALDVR] Unable to create CEC_Event_Thread  thread\n");
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    *handle = (int)Cec_driverCtx_ptr;

    pthread_mutex_unlock(&Cec_DriverMutex);

    return ret;
}


/**
 * @brief close an instance of CEC driver.  
 * This function should close the currently opened driver instance.
 *
 * @param [in]  :  handle returned from the HdmiCecOpen() function.
 * @param [out] :  None 
 *
 * @return Error Code:  
 */
int HdmiCecClose(int handle)
{
    int ret = HDMI_CEC_IO_SUCCESS;

    printf("[HALDVR] %s \n",__func__);   
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }
    pthread_mutex_unlock(&Cec_DriverMutex);
    poll_thread_stop =1;
    int err = pthread_join(CEC_Event_Thread, NULL);
    if(err)
    {
        printf("[HALDVR] pthread_join returned error\n");
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    pthread_mutex_lock(&Cec_DriverMutex);
    if (ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_OPTION_ENALBE_CEC, 0) < 0) {
        printf("[HALDVR] CEC_IOC_SET_OPTION_ENALBE_CEC returned error %d\n",ret);
    }
    if (ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_SET_OPTION_SYS_CTRL, 0) < 0) {
        printf("[HALDVR] CEC_IOC_SET_OPTION_SYS_CTRL returned error %d\n",ret);
    }
    close(Cec_driverCtx_ptr->cecFd);
    Cec_driverCtx_ptr->cecFd = -1;
    Cec_driverCtx_ptr->logicalAddress =  -1;
    Cec_driverCtx_ptr->rxCB = NULL;
    Cec_driverCtx_ptr->rxCBdata =NULL;
    Cec_driverCtx_ptr->txCB = NULL;

    Cec_driverCtx_ptr->txCBdata = NULL;
    Cec_driverCtx_ptr = NULL;
    pthread_mutex_unlock(&Cec_DriverMutex);
    return ret;
}

/**
 * @brief Get the Physical Address obtained by the driver.
 *
 * This function get the Physical address for the specified device type.
 *
 * @param [in]     :  handle returned from the HdmiCecOpen() function.
 * @param [out]    :  physical address acquired
 *
 * @return None.
 */
void HdmiCecGetPhysicalAddress(int handle, unsigned int *physicalAddress)

{
    unsigned int phy_address=0;
    int ret = 0;

    printf("[HALDVR] %s \n",__func__);

    if(physicalAddress == NULL)
    {
        printf("[HALDVR] NULL pointer passed\n");
        return;
    }
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return;
    }
    ret = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_GET_PHYSICAL_ADDR, &phy_address);
    if (ret != 0)
    { 
        printf("[HALDVR] CEC_IOC_GET_PHYSICAL_ADDR returned error %d\n",ret);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return;
    }
    printf("[HALDVR] %s: Physical address: %d \n",__func__, phy_address);
    *physicalAddress = phy_address;

    pthread_mutex_unlock(&Cec_DriverMutex);

}


/**
 * @brief Add one Logical Addresses to be used by host device.
 *
 * This function can block until the intended logical address is secured by
 * the driver.
 *
 * In driver implementation, this API would trigger driver sending a POLL
 * CEC packet to the CEC Bus,
 *
 * Packet::HeaderBlock::Initiator   =  Requested LogicalAddress.
 * Packet::HeaderBlock::Destination =  Requested LogicalAddress.
 * Packet::DataBlock   				=  Empty.
 *
 * The function shall return HDMI_CEC_IO_SUCCESS if the POLL message is sent
 * successfully and not ACK'd by any device on the bus. From this point on the
 * driver shall forward all received messages with destination being the acquired
 * logical address. Driver should ACK all POLL messsges destined to this logical
 * address.
 *
 * The function shall return HDMI_CEC_IO_LOGICALADDRESS_UNAVAILABLE if the POLL
 * message is sent and ACK'd by a device on the bus.
 *
 * The function shall return relevant error code if the POLL message is not sent
 * successfully.
 *
 *
 * @param [in]  :  handle returned from the HdmiCecOpen() function.
 * @param [in]  :  logicalAddresses to be acquired.
 * @param [out] :  None
 *
 * @return Error Code: See above.
 */
int HdmiCecAddLogicalAddress(int handle, int logicalAddresses)
{
    int ret = HDMI_CEC_IO_SUCCESS;

    printf("[HALDVR] %s: Add logical address: %d\n",__func__,logicalAddresses);
    pthread_mutex_lock(&Cec_DriverMutex);

    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }
    int err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_ADD_LOGICAL_ADDR, logicalAddresses);
    if (err != 0)
    { 
        printf("[HALDVR] CEC_IOC_ADD_LOGICAL_ADDR returned error %d\n",ret);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    else {
        printf("[HALDVR] %s: CEC_IOC_ADD_LOGICAL_ADDR Successs !!!\n",__func__);
        Cec_driverCtx_ptr->logicalAddress = logicalAddresses;
    }

    pthread_mutex_unlock(&Cec_DriverMutex);
    return ret;
}


/**
 * @brief Clear the Logical Addresses claimed by host device.
 *
 * This function release the previously acquired logical address.  Once
 * released, driver should not ACK any POLL message destined to the
 * released address.
 *
 * @param [in]  :  handle returned from the HdmiCecOpen() function.
 * @param [in]  :  logicalAddresses to be released.
 * @param [out] :  None
 *
 * @return Error Code:  see above.
 */
int HdmiCecRemoveLogicalAddress(int handle, int logicalAddresses)
{
    int ret = HDMI_CEC_IO_SUCCESS;

    printf("[HALDVR] %s: Remove logical address %d \n",__func__,logicalAddresses);
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }
    int err = ioctl(Cec_driverCtx_ptr->cecFd, CEC_IOC_CLR_LOGICAL_ADDR, 0x0);
    if (err != 0)
    { 
        printf("[HALDVR] CEC_IOC_CLR_LOGICAL_ADDR returned error %d\n",ret);
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    else {
        Cec_driverCtx_ptr->logicalAddress = -1;
    }
    pthread_mutex_unlock(&Cec_DriverMutex);
    return ret;

}


/**
 * @brief Get the Logical Address obtained by the driver.
 *
 * This function get the logical address for the specified device type.
 *
 * @param [in]     :  handle returned from the HdmiCecOpen() function.
 * @param [in]     :  device type (tuner, record, playback etc.).
 * @param [out]    :  logical address acquired
 *
 * @return Error Code:  If error code is returned, the get is failed.
 */
int HdmiCecGetLogicalAddress(int handle, int devType,  int *logicalAddress)
{
    pthread_mutex_lock(&Cec_DriverMutex);

    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }

#ifdef BUILD_AML_STB
    /* No IOCTL support available */
    FILE * fp = popen("cat /sys/class/cec/log_addr","r");
    if (fp) {
        char buffer[16] = {'\0'};
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = '\0';
            printf("[HALDVR] buffer = '%s' atoi = %d\n", buffer, strtol(buffer, NULL, 16));
            *logicalAddress = (int)strtol(buffer, NULL, 16);
        }
        pclose(fp);
    }
#else
    *logicalAddress = Cec_driverCtx_ptr->logicalAddress;
#endif
    printf("[HALDVR] %s: logical address %d \n",__func__,*logicalAddress);

    pthread_mutex_unlock(&Cec_DriverMutex);
    return HDMI_CEC_IO_SUCCESS;
}


/**
 * @brief Sets CEC packet Receive callback.  
 *
 * This function sets a callback function to be invoked for each packet arrival.   
 * The packet contained in the buffer is expected to follow this format:
 *
 * (ref <HDMI Specification 1-4> Section <CEC 6.1>)
 * 
 * complete packet = header block + data block;
 * header block = destination logical address (4-bit) + source address (4-bit)
 * data   block = opcode block (8-bit) + oprand block (N-bytes)                 
 *
 * |------------------------------------------------
 * | header block  |          data blocks          |
 * |------------------------------------------------
 * |3|2|1|0|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|  
 * |------------------------------------------------
 * | Dest  |  src  |  opcode block | operand block |
 * |------------------------------------------------
 *
 * when receiving, the returned buffer should not contain EOM and ACK bits.
 * 
 * When transmitting, it is driver's responsibility to insert EOM bit and ACK bit 
 * for each header or data block 
 *
 * When HdmiCecSetRxCallback is called, it replaces the previous set cbfunc and data
 * values.  Setting a value of (cbfunc=null) turns off the callback.
 *
 * This function should block if callback invocation is in progress.
 *
 * @param [in]     :  handle returned from the HdmiCecOpen(() function.
 * @param [in]     :  cbfunc to be invoked when a complete packet is received.
 * @param [in]     :  data, used when invoking callback function. 
 *
 * @return Error Code:  If error code is returned, the set is failed.
 */
int HdmiCecSetRxCallback(int handle, HdmiCecRxCallback_t cbfunc, void *data)

{
    printf("[HALDVR] %s \n",__func__);
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }

    Cec_driverCtx_ptr->rxCB = cbfunc;
    Cec_driverCtx_ptr->rxCBdata = data;

    pthread_mutex_unlock(&Cec_DriverMutex);

    return HDMI_CEC_IO_SUCCESS;

}


/**
 * @brief Sets CEC packet Transmit callback.
 *
 * This function sets a callback function to be invoked once the async transmit
 * result is available. This is only necessary if application choose to transmit
 * the packet asynchronously.
 *
 * This function should block if callback invocation is in progress.
 *
 * @param[in] handle Returned from the HdmiCecOpen(() function.
 * @param[in] cbfunc Function pointer to be invoked when a complete packet is received.
 * @param[in] data It is used when invoking callback function.
 *
 * @return Error Code:  If error code is returned, the set is failed.
 */
int HdmiCecSetTxCallback(int handle, HdmiCecTxCallback_t cbfunc, void *data) 
{
    printf("[HALDVR] %s \n",__func__);
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }

    Cec_driverCtx_ptr->txCB = cbfunc;
    Cec_driverCtx_ptr->txCBdata = data;

    pthread_mutex_unlock(&Cec_DriverMutex);

    return HDMI_CEC_IO_SUCCESS;
}


/**
 * @brief Writes CEC packet onto bus.  
 *
 * This function writes a complete CEC packet onto the CEC bus and wait for ACK.
 * application should check for result when return value of the function is 0;
 *
 * The bytes in @param buf that is to be transmitted should follow the buffer
 * byte format required for receiving buffer. (See detailed description from 
 * HdmiCecSetRxCallback)
 *
 * @param [in]     :  handle returned from the HdmiCecOpen(() function.
 * @param [in]     :  buf contains a complete CEC packet.
 * @param [in]     :  len number of bytes in the packet.
 * @param [out]    :  result of the send. Possbile results are SENT_AND_ACKD, 
 *                    SENT_BUT_NOT_ACKD (e.g. no follower at the destionation),
 *                    SENT_FAILED (e.g. collision).
 *
 * @return Error Code:  If error code is returned, the transmit did not happen.
 */
int HdmiCecTx(int handle, const unsigned char *buf, int len, int *result)
{
    int ret = HDMI_CEC_IO_SUCCESS;
    pthread_mutex_lock(&Cec_DriverMutex);
    if ((handle != ((int)Cec_driverCtx_ptr))) {\
        printf("[HALDVR] Assert Failed at [%s][%d]\r\n", __FUNCTION__, __LINE__);
        pthread_mutex_unlock(&Cec_DriverMutex);
        *result = HDMI_CEC_IO_INVALID_ARGUMENT;
        return HDMI_CEC_IO_INVALID_ARGUMENT;
    }

    int err = write(Cec_driverCtx_ptr->cecFd,buf,len);
    if (err != CEC_FAIL_NONE && err != CEC_FAIL_NACK ) {
        if(len > 1)printf("[HALDVR] Cec write failed err %d\n",err);
        *result = HDMI_CEC_IO_GENERAL_ERROR;
        ret = HDMI_CEC_IO_GENERAL_ERROR;
    }
    else {
        if(len > 1)
        {
            printf("[HALDVR] %s: CEC Write message success \n MSG: ",__func__);
            for(int i=0; i<len; i++)
                printf(" 0x%x ",buf[i]);
            printf("\n");
        }
        if (err == CEC_FAIL_NACK ) {
            *result = HDMI_CEC_IO_SENT_BUT_NOT_ACKD;
        }
        ret = HDMI_CEC_IO_SUCCESS;

    }
    pthread_mutex_unlock(&Cec_DriverMutex);

    return ret;
}


/**
 * @brief Writes CEC packet onto bus asynchronously.
 *
 * This function writes a complete CEC packet onto the CEC bus but does not wait
 * for ACK. The result will be reported via HdmiCecRxCallback_t if return value
 * of this function is 0.
 *
 * @param[in] handle Handle returned from the HdmiCecOpen(() function.
 * @param[in] buf Buffer contains a complete CEC packet.
 * @param[in] len Number of bytes in the packet.
 *
 * @return Error Code:  If error code is returned, the transmit did not happen.
 */
int HdmiCecTxAsync(int handle, const unsigned char *buf, int len)
{
    printf("[HALDVR] HdmiCecTxAsync: no implementation\n");
    return HDMI_CEC_IO_SENT_FAILED;
}

/* Deprecated */
int HdmiCecSetLogicalAddress(int handle, int *logicalAddresses, int num)
{
    ERR("Deprecated...\n");
    return 0;
}
