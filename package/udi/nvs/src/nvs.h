//
// Created by Bruce on 2019-04-26.
//

#ifndef UDI_NVS_H
#define UDI_NVS_H

#include <stdint.h>

/**
 * @brief Mode of opening the non-volatile storage
 *
 */
typedef enum {
    NVS_READONLY,  /*!< Read only */
    NVS_READWRITE  /*!< Read and write */
} nvs_open_mode;

typedef uint32_t* nvs_handle;
typedef int32_t  udi_err_t;

/* NVS Error Code */
#define NVS_ERR_CODE                         (udi_err_t)0x81000000
#define NVS_OK                               (udi_err_t)0
#define NVS_ERR_OPEN_ALLOC_CONTEXT           (udi_err_t)(0x0001 | NVS_ERR_CODE)       // NVS OPEN ALLOC CONTEXT Err
#define NVS_ERR_OPEN_NAME_NULL               (udi_err_t)(0x0002 | NVS_ERR_CODE)       // NVS OPEN NAME NULL Err
#define NVS_ERR_OPEN_MALLOC                  (udi_err_t)(0x0003 | NVS_ERR_CODE)       // NVS OPEN MALLOC NULL Err
#define NVS_ERR_OPEN_LOAD                    (udi_err_t)(0x0004 | NVS_ERR_CODE)       // NVS OPEN LOAD UCI ERR
#define NVS_CONTEXT_HANDLE_NULL              (udi_err_t)(0x0005 | NVS_ERR_CODE)       // NVS HANDLE NULL
#define NVS_ERR_UCI_INTERNAL                 (udi_err_t)(0x0006 | NVS_ERR_CODE)       // NVS UCI INTERNAL

udi_err_t udi_nvs_open(const char* name, nvs_open_mode open_mode, nvs_handle *out_handle);

udi_err_t udi_nvs_set(nvs_handle handle, const char* key, const void* value, size_t length);

udi_err_t udi_nvs_get(nvs_handle handle, const char* key, void** out_value, size_t* length);

udi_err_t udi_nvs_erase_key(nvs_handle handle, const char* key);

udi_err_t udi_nvs_commit(nvs_handle handle);

void udi_nvs_close(nvs_handle handle);

#endif //UDI_NVS_H
