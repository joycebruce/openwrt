//
// Created by Bruce on 2019-04-26.
//
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <uci.h>


#include "nvs.h"

typedef struct nvs_ctx
{
    struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_section *sec;
}nvs_context;

udi_err_t udi_nvs_open(const char* name, nvs_open_mode open_mode, nvs_handle *out_handle)
{
    nvs_context *nvs_ctx = NULL;
    struct uci_section *sec = NULL;

    if(name == NULL)
    {
        return NVS_ERR_OPEN_NAME_NULL;
    }

    nvs_ctx = (nvs_context *) malloc(sizeof(nvs_context));
    if(nvs_ctx == NULL)
    {
        return NVS_ERR_OPEN_MALLOC;
    }

    memset(nvs_ctx, 0, sizeof(nvs_context));
    nvs_ctx->ctx = uci_alloc_context();
    if(NULL == nvs_ctx->ctx)
    {
        free(nvs_ctx);
        return NVS_ERR_OPEN_ALLOC_CONTEXT;
    }

    if(UCI_OK != uci_load(nvs_ctx->ctx, name, &nvs_ctx->pkg))
    {
        uci_free_context(nvs_ctx->ctx);
        free(nvs_ctx);
        return NVS_ERR_OPEN_LOAD;
    }

    /* setup section */
    nvs_ctx->sec = uci_lookup_section(nvs_ctx->ctx, nvs_ctx->pkg, name);
    if(sec == NULL)
    {
        uci_add_section(nvs_ctx->ctx, nvs_ctx->pkg, name, &nvs_ctx->sec);
    }

    *out_handle = (nvs_handle)nvs_ctx;
    return NVS_OK;
}

udi_err_t udi_nvs_set(nvs_handle handle, const char* key, const void* value, size_t length)
{
    nvs_context *nvs_ctx = NULL;
    struct uci_ptr ptr;

    nvs_ctx = (nvs_context *)handle;
    if(nvs_ctx == NULL)
    {
        return NVS_CONTEXT_HANDLE_NULL;
    }

    memset(&ptr, 0, sizeof(struct uci_ptr));
    ptr.package = nvs_ctx->pkg->e.name;
    ptr.section = nvs_ctx->sec->e.name;
    ptr.option = (const char *)key;
    ptr.value = (const char *)value;
    ptr.s = nvs_ctx->sec;
    ptr.p = nvs_ctx->pkg;
    return uci_set(nvs_ctx->ctx, &ptr) ? NVS_ERR_UCI_INTERNAL:NVS_OK;
}

udi_err_t udi_nvs_get(nvs_handle handle, const char* key, void** out_value, size_t* length)
{
    nvs_context *nvs_ctx = NULL;
    struct uci_ptr ptr;

    nvs_ctx = (nvs_context *)handle;
    if(nvs_ctx == NULL)
    {
        return NVS_CONTEXT_HANDLE_NULL;
    }

    memset(&ptr, 0, sizeof(struct uci_ptr));
    ptr.package = nvs_ctx->pkg->e.name;
    ptr.section = nvs_ctx->sec->e.name;
    ptr.option = (const char *)key;
    ptr.s = nvs_ctx->sec;
    ptr.p = nvs_ctx->pkg;

    if(UCI_OK != uci_lookup_ptr(nvs_ctx->ctx, &ptr, NULL, false))
    {
        return NVS_ERR_UCI_INTERNAL;
    }

    if(NULL == ptr.o)
    {
        return NVS_ERR_UCI_INTERNAL;
    }

    *out_value = ptr.o->v.string;
    *length = strlen(*out_value);

    return NVS_OK;
}

udi_err_t udi_nvs_erase_key(nvs_handle handle, const char* key)
{
    nvs_context *nvs_ctx = (nvs_context *) handle;
    struct uci_ptr ptr;

    memset(&ptr, 0, sizeof(struct uci_ptr));
    ptr.package = nvs_ctx->pkg->e.name;
    ptr.section = nvs_ctx->sec->e.name;
    ptr.option = (const char *) key;
    ptr.s = nvs_ctx->sec;
    ptr.p = nvs_ctx->pkg;

    if (UCI_OK != uci_lookup_ptr(nvs_ctx->ctx, &ptr, NULL, false))
    {
        return NVS_ERR_UCI_INTERNAL;
    }

    return uci_delete(nvs_ctx->ctx, &ptr) ? NVS_ERR_UCI_INTERNAL : NVS_OK;
}

udi_err_t udi_nvs_commit(nvs_handle handle)
{
    nvs_context *nvs_ctx = (nvs_context *)handle;
    return uci_commit(nvs_ctx->ctx, &nvs_ctx->pkg, true) ? NVS_ERR_UCI_INTERNAL:NVS_OK;
}

void udi_nvs_close(nvs_handle handle)
{
    nvs_context *nvs_ctx = NULL;

    nvs_ctx = (nvs_context *)handle;
    if(nvs_ctx == NULL)
    {
        return;
    }

    uci_unload(nvs_ctx->ctx, nvs_ctx->pkg);
    uci_free_context(nvs_ctx->ctx);
    free(nvs_ctx);

    return;
}