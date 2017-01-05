/*
 * openbsd_driver.c: core driver methods for managing OpenBSD VM's
 *
 * Copyright (C) 2016 Sergey Bronnikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 * Sergey Bronnikov <sergeyb@bronevichok.ru>
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "nodeinfo.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virlog.h"
#include "vircommand.h"
#include "viruri.h"
#include "virstats.h"
#include "virstring.h"
#include "openbsd_vmm_driver.h"

#include "machine/vmmvar.h"

#define VIR_FROM_THIS VIR_FROM_OPENBSD_VMM

#define __OPENBSD_VMM_DRIVER_H__

VIR_LOG_INIT("openbsd.openbsd_driver");

/* Free all memory associated with a openbsd_driver structure */
void openbsdFreeDriver(struct openbsd_driver *driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->caps);
    VIR_FREE(driver);
}

static int openbsdConnectGetMaxVcpus(virConnectPtr conn, const char *type);
static int openbsdGetProcessInfo(unsigned long long *cpuTime, int vpsid);
static int openbsdDomainGetMaxVcpus(virDomainPtr dom);
/*
static int openbsdDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus);
static int openbsdDomainSetMemoryInternal(virDomainObjPtr vm,
                                         unsigned long long memory);
*/
static int openbsdGetVEStatus(virDomainObjPtr vm, int *status, int *reason);

static void openbsdDriverLock(struct openbsd_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void openbsdDriverUnlock(struct openbsd_driver *driver)
{
    virMutexUnlock(&driver->lock);
}


static int openbsdSetInitialConfig(virDomainDefPtr vmdef)
{
    int ret = -1;
    int vpsid;
    char * confdir = NULL;
    virCommandPtr cmd = NULL;

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
	VIR_FREE(confdir);

 	return ret;
}


static virDomainPtr openbsdDomainLookupByID(virConnectPtr conn,
                                           int id)
{
    struct openbsd_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByID(driver->domains, id);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int openbsdConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct  openbsd_driver *driver = conn->privateData;
    openbsdDriverLock(driver);
    *version = driver->version;
    openbsdDriverUnlock(driver);
    return 0;
}

static char *openbsdConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}

static char *openbsdDomainGetOSType(virDomainPtr dom)
{
    struct  openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, virDomainOSTypeToString(vm->def->os.type)));

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static virDomainPtr openbsdDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid)
{
    struct  openbsd_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}


static virDomainPtr openbsdDomainLookupByName(virConnectPtr conn,
                                             const char *name)
{
    struct openbsd_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, name);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}


static int openbsdDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int state;
    int ret = -1;

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openbsdGetVEStatus(vm, &state, NULL) == -1)
        goto cleanup;
    info->state = state;

    if (info->state != VIR_DOMAIN_RUNNING) {
        info->cpuTime = 0;
    } else {
        if (openbsdGetProcessInfo(&(info->cpuTime), dom->id) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot read cputime for domain %d"), dom->id);
            goto cleanup;
        }
    }

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
openbsdDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = openbsdGetVEStatus(vm, state, reason);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int openbsdDomainIsActive(virDomainPtr dom)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openbsdDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int openbsdDomainIsPersistent(virDomainPtr dom)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    openbsdDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int openbsdDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
}

static char *openbsdDomainGetXMLDesc(virDomainPtr dom, unsigned int flags) {
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    // Flags checked by virDomainDefFormat
    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(vm->def, driver->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


/*
static int
openbsdDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;


    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openbsdGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;

    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    dom->id = -1;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
*/


/*
static int
openbsdDomainShutdown(virDomainPtr dom)
{
    return openbsdDomainShutdownFlags(dom, 0);
}
*/

/*
static int
openbsdDomainDestroy(virDomainPtr dom)
{
    return openbsdDomainShutdownFlags(dom, 0);
}
*/

/*
static int
openbsdDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    return openbsdDomainShutdownFlags(dom, flags);
}
*/

/*
static int openbsdDomainReboot(virDomainPtr dom,
                              unsigned int flags)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (openbsdGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(prog, NULL) < 0)
        goto cleanup;
    ret = 0;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
*/


/*
static virDomainPtr
openbsdDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct openbsd_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    openbsdDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         parse_flags)) == NULL)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, vmdef,
                                   driver->xmlopt,
                                   0, NULL)))
        goto cleanup;
    vmdef = NULL;
    vm->persistent = 1;

    if (openbsdSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (vm->def->nfss == 1) {
        if (openbsdSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }

    if (openbsdSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (openbsdDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;

    if (virDomainDefHasVcpusOffline(vm->def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpu count must equal maximum"));
        goto cleanup;
    }
    if (virDomainDefGetVcpusMax(vm->def)) {
        if (openbsdDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
             goto cleanup;
        }
    }

    if (vm->def->mem.cur_balloon > 0) {
        if (openbsdDomainSetMemoryInternal(vm, vm->def->mem.cur_balloon) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set memory size"));
             goto cleanup;
        }
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = -1;

 cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
    openbsdDriverUnlock(driver);
    return dom;
}
*/


/*
static virDomainPtr
openbsdDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return openbsdDomainDefineXMLFlags(conn, xml, 0);
}
*/


static virDomainPtr
openbsdDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct openbsd_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    //const char *progstart[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINEL, NULL};
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    openbsdDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                         parse_flags)) == NULL)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    vmdef = NULL;
    vm->persistent = 1;

    if (openbsdSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

/*
    if (vm->def->nfss == 1) {
        if (openbsdSetDiskQuota(vm->def, vm->def->fss[0], true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set disk quota"));
            goto cleanup;
        }
    }
*/

/*
    if (openbsdSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }
*/

/*
    if (openbsdDomainSetNetworkConfig(conn, vm->def) < 0)
        goto cleanup;
*/

    //openbsdSetProgramSentinal(progstart, vm->def->name);

    //if (virRun(progstart, NULL) < 0)
    //    goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

/*
    if (virDomainDefGetVcpusMax(vm->def) > 0) {
        if (openbsdDomainSetVcpusInternal(vm, virDomainDefGetVcpusMax(vm->def)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not set number of vCPUs"));
            goto cleanup;
        }
    }
*/

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
    openbsdDriverUnlock(driver);
    return dom;
}


/*
static int
openbsdDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct openbsd_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VZCTL, "--quiet", "start", PROGRAM_SENTINEL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openbsdDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, dom->name);
    openbsdDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching id"));
        goto cleanup;
    }

    if (status != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("domain is not in shutoff state"));
        goto cleanup;
    }

    openbsdSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    dom->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}
*/


/*
static int
openbsdDomainCreate(virDomainPtr dom)
{
    return openbsdDomainCreateWithFlags(dom, 0);
}
*/


/*
static int
openbsdDomainUndefine(virDomainPtr dom)
{
    return openbsdDomainUndefineFlags(dom, 0);
}
*/


static int openbsdConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    const char *type)
{
    if (type == NULL || STRCASEEQ(type, "openbsd"))
        return VMM_MAX_VCPUS_PER_VM;

    virReportError(VIR_ERR_INVALID_ARG,
                   _("unknown type '%s'"), type);
    return -1;
}


static int
openbsdDomainGetVcpusFlags(virDomainPtr dom ATTRIBUTE_UNUSED,
                          unsigned int flags)
{
    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported flags (0x%x)"), flags);
        return -1;
    }

    return openbsdConnectGetMaxVcpus(NULL, "openbsd");
}


static int openbsdDomainGetMaxVcpus(virDomainPtr dom)
{
    return openbsdDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}


/*
static int openbsdDomainSetVcpusInternal(virDomainObjPtr vm,
                                        unsigned int nvcpus)
{
    char        str_vcpus[32];
    const char *prog[] = { VZCTL, "--quiet", "set", PROGRAM_SENTINEL,
                           "--cpus", str_vcpus, "--save", NULL };
    unsigned int pcpus;
    pcpus = openbsdGetNodeCPUs();
    if (pcpus > 0 && pcpus < nvcpus)
        nvcpus = pcpus;

    snprintf(str_vcpus, 31, "%d", nvcpus);
    str_vcpus[31] = '\0';

    openbsdSetProgramSentinal(prog, vm->def->name);
    if (virRun(prog, NULL) < 0)
        return -1;

    if (virDomainDefSetVcpusMax(vm->def, nvcpus) < 0)
        return -1;

    if (virDomainDefSetVcpus(vm->def, nvcpus) < 0)
        return -1;

    return 0;
}
*/


static virDrvOpenStatus openbsdConnectOpen(virConnectPtr conn,
                                          virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                          virConfPtr conf ATTRIBUTE_UNUSED)
{
    struct openbsd_driver *driver;
    // FIXME: virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        if (!(conn->uri = virURIParse("openbsd:///system")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        /* If scheme isn't 'openbsd', then its for another driver */
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "openbsd"))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't /system, then they typoed, so tell them correct path */
        if (conn->uri->path == NULL ||
            STRNEQ(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected OpenVZ URI path '%s', try openbsd:///system"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (VIR_ALLOC(driver) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

/*
    if (!(driver->caps = openbsdCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = virDomainXMLOptionNew(&openbsdDomainDefParserConfig,
                                                 NULL, NULL)))
        goto cleanup;

    if (openbsdLoadDomains(driver) < 0)
        goto cleanup;

    if (openbsdExtractVersion(driver) < 0)
        goto cleanup;
*/

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    openbsdFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};


static int openbsdConnectClose(virConnectPtr conn)
{
    struct openbsd_driver *driver = conn->privateData;

    openbsdFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *openbsdConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "OpenBSD";
}

static int openbsdConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Encryption is not relevant / applicable */
    return 0;
}

static int openbsdConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
openbsdConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static char *openbsdConnectGetCapabilities(virConnectPtr conn) {
    struct openbsd_driver *driver = conn->privateData;
    char *ret;

    openbsdDriverLock(driver);
    ret = virCapabilitiesFormatXML(driver->caps);
    openbsdDriverUnlock(driver);

    return ret;
}


/*
static int openbsdConnectListDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    int *ids, int nids)
{
	return 0;
}
*/


static int openbsdConnectNumOfDomains(virConnectPtr conn)
{
    struct openbsd_driver *driver = conn->privateData;
    int n;

    openbsdDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
    openbsdDriverUnlock(driver);

    return n;
}


/*
static int openbsdConnectListDefinedDomains(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           char **const names, int nnames) {

    struct parse_result *res = id->NULL;
    struct parse_result *res = name->NULL;
    get_info_vm(res->id, res->name, 0);
    return rc;
}
*/


static int openbsdGetProcessInfo(unsigned long long *cpuTime, int vpsid)
{
    return 0;
}


static int openbsdConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct openbsd_driver *driver =  conn->privateData;
    int n;

    openbsdDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
    openbsdDriverUnlock(driver);

    return n;
}


/*
static int
openbsdDomainSetMemoryInternal(virDomainObjPtr vm,
                              unsigned long long mem)
{
    return -1;
}
*/


/*
static int
openbsdDomainGetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int *nparams,
                                unsigned int flags)
{
    // FIXME
    return -1;
}
*/


/*
static int
openbsdDomainSetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    return -1;
}
*/


static int
openbsdGetVEStatus(virDomainObjPtr vm, int *status, int *reason)
{
    char *outbuf;
    char *line;
    int state;
    int ret = -1;

    state = virDomainObjGetState(vm, reason);

    // FIXME: outbuf

    if (STREQ(outbuf, "running")) {
        if (state == VIR_DOMAIN_PAUSED)
            *status = state;
        else
            *status = VIR_DOMAIN_RUNNING;
    } else {
        *status = VIR_DOMAIN_SHUTOFF;
    }

    ret = 0;

 cleanup:
    VIR_FREE(outbuf);
    return ret;
}


static int
openbsdConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct openbsd_driver *driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    openbsdDriverLock(driver);
    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 NULL, flags);
    openbsdDriverUnlock(driver);

    return ret;
}


static int
openbsdNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                  virNodeInfoPtr nodeinfo)
{
    return nodeGetInfo(nodeinfo);
}


static int
openbsdNodeGetCPUStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                      int cpuNum,
                      virNodeCPUStatsPtr params,
                      int *nparams,
                      unsigned int flags)
{
    return virHostCPUGetStats(cpuNum, params, nparams, flags);
}


static int
openbsdNodeGetMemoryStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                         int cellNum,
                         virNodeMemoryStatsPtr params,
                         int *nparams,
                         unsigned int flags)
{
    return virHostMemGetStats(cellNum, params, nparams, flags);
}


static int
openbsdNodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                             unsigned long long *freeMems,
                             int startCell,
                             int maxCells)
{
    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}


static unsigned long long
openbsdNodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem;
    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;
    return freeMem;
}


static int
openbsdNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                    unsigned char **cpumap,
                    unsigned int *online,
                    unsigned int flags)
{
    return virHostCPUGetMap(cpumap, online, flags);
}


static virHypervisorDriver openbsdHypervisorDriver = {
    .name = "OPENBSD",
    .connectOpen = openbsdConnectOpen, /* implemented */
    .connectClose = openbsdConnectClose, /* implemented */
    .connectGetType = openbsdConnectGetType, /* implemented */
    .connectGetVersion = openbsdConnectGetVersion, /* implemented */
    .connectGetMaxVcpus = openbsdConnectGetMaxVcpus, /* implemented */
    .nodeGetInfo = openbsdNodeGetInfo, /* implemented */
    .nodeGetCPUStats = openbsdNodeGetCPUStats, /* implemented */
    .nodeGetMemoryStats = openbsdNodeGetMemoryStats, /* implemented */
    .nodeGetCellsFreeMemory = openbsdNodeGetCellsFreeMemory, /* implemented */
    .nodeGetFreeMemory = openbsdNodeGetFreeMemory, /* implemented */
    .nodeGetCPUMap = openbsdNodeGetCPUMap, /* implemented */
    .connectGetCapabilities = openbsdConnectGetCapabilities, /* implemented */
    //.connectListDomains = openbsdConnectListDomains,
    .connectNumOfDomains = openbsdConnectNumOfDomains, /* implemented */
    .connectListAllDomains = openbsdConnectListAllDomains,
    //.domainCreateXML = openbsdDomainCreateXML,
    .domainLookupByID = openbsdDomainLookupByID, /* implemented */
    .domainLookupByUUID = openbsdDomainLookupByUUID, /* implemented */
    .domainLookupByName = openbsdDomainLookupByName, /* implemented */
    //.domainShutdown = openbsdDomainShutdown,
    //.domainShutdownFlags = openbsdDomainShutdownFlags,
    //.domainReboot = openbsdDomainReboot,
    //.domainDestroy = openbsdDomainDestroy,
    //.domainDestroyFlags = openbsdDomainDestroyFlags,
    .domainGetOSType = openbsdDomainGetOSType, /* implemented */
    //.domainGetMemoryParameters = openbsdDomainGetMemoryParameters,
    //.domainSetMemoryParameters = openbsdDomainSetMemoryParameters,
    .domainGetInfo = openbsdDomainGetInfo, /* implemented */
    .domainGetState = openbsdDomainGetState, /* implemented */
    .domainGetVcpusFlags = openbsdDomainGetVcpusFlags, /* implemented */
    .domainGetMaxVcpus = openbsdDomainGetMaxVcpus, /* implemented */
    .domainGetXMLDesc = openbsdDomainGetXMLDesc, /* implemented */
    //.connectListDefinedDomains = openbsdConnectListDefinedDomains,
    .connectNumOfDefinedDomains = openbsdConnectNumOfDefinedDomains, /* implemented */
    //.domainCreate = openbsdDomainCreate,
    //.domainCreateWithFlags = openbsdDomainCreateWithFlags,
    //.domainDefineXML = openbsdDomainDefineXML,
    //.domainDefineXMLFlags = openbsdDomainDefineXMLFlags,
    //.domainUndefine = openbsdDomainUndefine,
    .connectIsEncrypted = openbsdConnectIsEncrypted, /* implemented */
    .connectIsSecure = openbsdConnectIsSecure, /* implemented */
    .domainIsActive = openbsdDomainIsActive, /* implemented */
    .domainIsPersistent = openbsdDomainIsPersistent, /* implemented */
    .domainIsUpdated = openbsdDomainIsUpdated, /* implemented */
    .connectIsAlive = openbsdConnectIsAlive, /* implemented */
    .connectGetHostname = openbsdConnectGetHostname, /* implemented */
};


static virConnectDriver openbsdConnectDriver = {
    .hypervisorDriver = &openbsdHypervisorDriver,
};


int openbsdRegister(void)
{
    return virRegisterConnectDriver(&openbsdConnectDriver,
                                    false);
}
