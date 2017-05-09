/*
 * openbsd_driver.c: core driver methods for managing OpenBSD VM's
 *
 * Copyright (C) 2017 Sergey Bronnikov
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
 * Author: Sergey Bronnikov <sergeyb@bronevichok.ru>
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
#include "virstring.h"
#include "viraccessapicheck.h"
#include "virtime.h"

#include "openbsd_vmm_driver.h"
#include "machine/vmmvar.h"

#define VIR_FROM_THIS VIR_FROM_OPENBSD_VMM

VIR_LOG_INIT("openbsd.openbsd_driver");

static virClassPtr openbsdDriverClass;
static virMutex openbsd_driver_lock;
static openbsdDriverPtr openbsd_driver;
static openbsdConnPtr openbsd_conn_list;

static openbsdDriverPtr
openbsdDriverObjNew(void)
{
    openbsdDriverPtr driver;

/*
    if (openbsdDriverInitialize() < 0)
        return NULL;
*/

    if (!(driver = virObjectLockableNew(openbsdDriverClass)))
        return NULL;

/*
    openbsdDomainDefParserConfig.priv = &driver->openbsdCaps;

    if (!(driver->caps = openbsdBuildCapabilities()) ||
        !(driver->xmlopt = virDomainXMLOptionNew(&openbsdDomainDefParserConfig,
                                                 &openbsdDomainXMLPrivateDataCallbacksPtr,
                                                 NULL)) ||
        !(driver->domains = virDomainObjListNew()) ||
        !(driver->domainEventState = virObjectEventStateNew()) ||
        (openbsdInitVersion(driver) < 0) ||
        (prlsdkConnect(driver) < 0)) {
        virObjectUnref(driver);
        return NULL;
    }
*/

    driver->hostsysinfo = virSysinfoRead();
    //ignore_value(prlsdkLoadDomains(driver));

    /* As far as waitDomainJob finally calls virReportErrorHelper
     * and we are not going to report it, reset it expicitly*/
    virResetLastError();

    return driver;
}


openbsdDriverPtr
openbsdGetDriverConnection(void)
{
    virMutexLock(&openbsd_driver_lock);
    if (!openbsd_driver)
        openbsd_driver = openbsdDriverObjNew();
    virObjectRef(openbsd_driver);
    virMutexUnlock(&openbsd_driver_lock);

    return openbsd_driver;
}


static virDrvOpenStatus
openbsdConnectOpen(virConnectPtr conn,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   virConfPtr conf ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    openbsdDriverPtr driver = NULL;
    openbsdConnPtr privconn = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme)
        return VIR_DRV_OPEN_DECLINED;

    if STREQ(conn->uri->scheme, "openbsd")
        return VIR_DRV_OPEN_DECLINED;

    if (STREQ(conn->uri->scheme, "openbsd") && STRNEQ(conn->driver->name, "openbsd"))
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    if (STRNEQ_NULLABLE(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected OpenBSD VMM URI path '%s', try openbsd:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (!(driver = openbsdGetDriverConnection()))
        return VIR_DRV_OPEN_ERROR;

    if (VIR_ALLOC(privconn) < 0)
        goto error;

    conn->privateData = privconn;
    privconn->driver = driver;

    if (!(privconn->closeCallback = virNewConnectCloseCallbackData()))
        goto error;

    virMutexLock(&openbsd_driver_lock);
    privconn->next = openbsd_conn_list;
    openbsd_conn_list = privconn;
    virMutexUnlock(&openbsd_driver_lock);

    return VIR_DRV_OPEN_SUCCESS;

 error:

    conn->privateData = NULL;
    virObjectUnref(driver);
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
};


static int openbsdConnectClose(virConnectPtr conn)
{
    openbsdConnPtr curr, *prev = &openbsd_conn_list;
    openbsdConnPtr privconn = conn->privateData;

    if (!privconn)
        return 0;

    virMutexLock(&openbsd_driver_lock);
    for (curr = openbsd_conn_list; curr; prev = &curr->next, curr = curr->next) {
        if (curr == privconn) {
            *prev = curr->next;
            break;
        }
    }

    virMutexUnlock(&openbsd_driver_lock);

    virObjectUnref(privconn->closeCallback);
    virObjectUnref(privconn->driver);
    VIR_FREE(privconn);
    conn->privateData = NULL;
    return 0;
}


static int
openbsdConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    openbsdConnPtr privconn = conn->privateData;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    *version = privconn->driver->openbsdVersion;
    return 0;
}

static char *openbsdConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

virDomainObjPtr
openbsdDomObjFromDomainRef(virDomainPtr domain)
{
    virDomainObjPtr vm;
    openbsdConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    openbsdDriverPtr driver = privconn->driver;

    vm = virDomainObjListFindByUUIDRef(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

#define VZ_JOB_WAIT_TIME (1000 * 30)

int
openbsdDomainObjBeginJob(virDomainObjPtr dom)
{
    openbsdDomObjPtr pdom = dom->privateData;
    unsigned long long now;
    unsigned long long then;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + VZ_JOB_WAIT_TIME;

    while (pdom->job.active) {
        if (virCondWaitUntil(&pdom->job.cond, &dom->parent.lock, then) < 0)
            goto error;
    }

    if (virTimeMillisNow(&now) < 0)
        return -1;

    pdom->job.active = true;
    pdom->job.started = now;
    pdom->job.elapsed = 0;
    pdom->job.progress = 0;
    pdom->job.hasProgress = false;
    return 0;

 error:
    if (errno == ETIMEDOUT)
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       "%s", _("cannot acquire state change lock"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));
    return -1;
}

void
openbsdDomainObjEndJob(virDomainObjPtr dom)
{
    openbsdDomObjPtr pdom = dom->privateData;

    pdom->job.active = false;
    pdom->job.cancelled = false;
    virCondSignal(&pdom->job.cond);
}

static int
openbsdEnsureDomainExists(virDomainObjPtr dom)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!dom->removing)
        return 0;

    virUUIDFormat(dom->def->uuid, uuidstr);
    virReportError(VIR_ERR_NO_DOMAIN,
                   _("no domain with matching uuid '%s' (%s)"),
                   uuidstr, dom->def->name);

    return -1;
}

static int
openbsdDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    //openbsdConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom;
    int ret = -1;
    bool job = false;

    virCheckFlags(0, -1);

    if (!(dom = openbsdDomObjFromDomainRef(domain)))
        return -1;

    if (virDomainCreateWithFlagsEnsureACL(domain->conn, dom->def) < 0)
        goto cleanup;

    if (openbsdDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (openbsdEnsureDomainExists(dom) < 0)
        goto cleanup;

    //if (prlsdkStart(dom) < 0)
    //    goto cleanup;

    //if (prlsdkUpdateDomain(privconn->driver, dom) < 0)
    //    goto cleanup;

    ret = 0;

 cleanup:
    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);

    return ret;
}

static int
openbsdDomainCreate(virDomainPtr domain)
{
    return openbsdDomainCreateWithFlags(domain, 0);
}

static virDomainPtr
openbsdDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    openbsdConnPtr privconn = conn->privateData;
    virDomainPtr retdom = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    openbsdDriverPtr driver = privconn->driver;
    bool job = false;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    dom = virDomainObjListFindByUUIDRef(driver->domains, def->uuid);
    if (dom == NULL) {
        virResetLastError();
/*
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
            if (prlsdkCreateVm(driver, def))
                goto cleanup;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported OS type: %s"),
                           virDomainOSTypeToString(def->os.type));
            goto cleanup;
        }
*/

/*
        if (!(dom = prlsdkAddDomainByUUID(driver, def->uuid)))
            goto cleanup;
*/
    } else {
        int state, reason;

        state = virDomainObjGetState(dom, &reason);

        if (state == VIR_DOMAIN_SHUTOFF &&
            reason == VIR_DOMAIN_SHUTOFF_SAVED) {

            /* PCS doesn't store domain config in managed save state file.
             * It's forbidden to change config for VMs in this state.
             * It's possible to change config for containers, but after
             * restoring domain will have that new config, not a config,
             * which domain had at the moment of virDomainManagedSave.
             *
             * So forbid this operation, if config is changed. If it's
             * not changed - just do nothing. */

            if (!virDomainDefCheckABIStability(dom->def, def)) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                               _("Can't change domain configuration "
                                 "in managed save state"));
                goto cleanup;
            }
        } else {
            if (openbsdDomainObjBeginJob(dom) < 0)
                goto cleanup;
            job = true;

            if (openbsdEnsureDomainExists(dom) < 0)
                goto cleanup;

/*
            if (prlsdkApplyConfig(driver, dom, def))
                goto cleanup;

            if (prlsdkUpdateDomain(driver, dom))
                goto cleanup;
*/
        }
    }

    retdom = virGetDomain(conn, def->name, def->uuid);
    if (retdom)
        retdom->id = def->id;

 cleanup:
    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);
    virDomainDefFree(def);
    return retdom;
}

static virDomainPtr
openbsdDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return openbsdDomainDefineXMLFlags(conn, xml, 0);
}

static int
openbsdDomainUndefineFlags(virDomainPtr domain,
                      unsigned int flags)
{
    //openbsdConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom = NULL;
    int ret = -1;
    bool job = false;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
                  VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);

    if (!(dom = openbsdDomObjFromDomainRef(domain)))
        return -1;

    if (virDomainUndefineFlagsEnsureACL(domain->conn, dom->def) < 0)
        goto cleanup;

    if (openbsdDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (openbsdEnsureDomainExists(dom) < 0)
        goto cleanup;

/*
    ret = prlsdkUnregisterDomain(privconn->driver, dom, flags);
*/

 cleanup:

    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);

    return ret;
}


static int
openbsdDomainUndefine(virDomainPtr domain)
{
    return openbsdDomainUndefineFlags(domain, 0);
}


static int
openbsdDomainReset(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr dom = NULL;
    int ret = -1;
    bool job = false;

    virCheckFlags(0, -1);

    if (!(dom = openbsdDomObjFromDomainRef(domain)))
        return -1;

    if (virDomainResetEnsureACL(domain->conn, dom->def) < 0)
        goto cleanup;

    if (openbsdDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (openbsdEnsureDomainExists(dom) < 0)
        goto cleanup;

/*
    ret = prlsdkReset(dom);
*/

 cleanup:
    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);
    return ret;
}


static int
openbsdDomainReboot(virDomainPtr domain, unsigned int flags)
{
    //openbsdConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom;
    int ret = -1;
    bool job = false;

    virCheckFlags(0, -1);

    if (!(dom = openbsdDomObjFromDomainRef(domain)))
        return -1;

    if (virDomainRebootEnsureACL(domain->conn, dom->def, flags) < 0)
        goto cleanup;

    if (openbsdDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (openbsdEnsureDomainExists(dom) < 0)
        goto cleanup;

/*
    if (prlsdkRestart(dom) < 0)
        goto cleanup;

    if (prlsdkUpdateDomain(privconn->driver, dom) < 0)
        goto cleanup;
*/

    ret = 0;

 cleanup:
    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);

    return ret;
}


static int
openbsdDomainDestroyFlags(virDomainPtr domain, unsigned int flags)
{
    //openbsdConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr dom;
    int ret = -1;
    bool job = false;

    virCheckFlags(0, -1);

    if (!(dom = openbsdDomObjFromDomainRef(domain)))
        return -1;

    if (virDomainDestroyFlagsEnsureACL(domain->conn, dom->def) < 0)
        goto cleanup;

    if (openbsdDomainObjBeginJob(dom) < 0)
        goto cleanup;
    job = true;

    if (openbsdEnsureDomainExists(dom) < 0)
        goto cleanup;

/*
    if (prlsdkKill(dom) < 0)
        goto cleanup;

    if (prlsdkUpdateDomain(privconn->driver, dom) < 0)
        goto cleanup;
*/

    ret = 0;

 cleanup:
    if (job)
        openbsdDomainObjEndJob(dom);
    virDomainObjEndAPI(&dom);

    return ret;
}


static int
openbsdDomainDestroy(virDomainPtr dom)
{
    return openbsdDomainDestroyFlags(dom, 0);
}

static virHypervisorDriver openbsdHypervisorDriver = {
    .name = "OPENBSD",
    .connectOpen = openbsdConnectOpen, /* 3.3.0 */
    .connectClose = openbsdConnectClose, /* 3.3.0 */
    .connectGetVersion = openbsdConnectGetVersion, /* 3.3.0 */
    .connectGetHostname = openbsdConnectGetHostname, /* 3.3.0 */
    .domainCreate = openbsdDomainCreate, /* 3.3.0 */
    .domainCreateWithFlags = openbsdDomainCreateWithFlags, /* 3.3.0 */
    .domainDefineXML = openbsdDomainDefineXML, /* 3.3.0 */
    .domainDefineXMLFlags = openbsdDomainDefineXMLFlags, /* 3.3.0 */
    .domainUndefine = openbsdDomainUndefine, /* 3.3.0 */
    .domainUndefineFlags = openbsdDomainUndefineFlags, /* 3.3.0 */
    .domainReset = openbsdDomainReset, /* 3.3.0 */
    .domainReboot = openbsdDomainReboot, /* 3.3.0 */
    .domainDestroy = openbsdDomainDestroy, /* 3.3.0 */
    .domainDestroyFlags = openbsdDomainDestroyFlags, /* 3.3.0 */
    //.connectListDomains = vzConnectListDomains, /* 3.3.0 */
    //.connectListDefinedDomains = vzConnectListDefinedDomains, /* 3.3.0 */
    //.connectListAllDomains = vzConnectListAllDomains, /* 3.3.0 */
    //.domainLookupByID = vzDomainLookupByID, /* 3.3.0 */
    //.domainLookupByUUID = vzDomainLookupByUUID, /* 3.3.0 */
    //.domainLookupByName = vzDomainLookupByName, /* 3.3.0 */
    //.domainGetOSType = vzDomainGetOSType, /* 3.3.0 */
    //.domainGetInfo = vzDomainGetInfo, /* 3.3.0 */
    //.domainGetState = vzDomainGetState, /* 3.3.0 */
    //.domainGetXMLDesc = vzDomainGetXMLDesc, /* 3.3.0 */
};


static virConnectDriver openbsdConnectDriver = {
    .hypervisorDriver = &openbsdHypervisorDriver,
};


static int
openbsdStateCleanup(void)
{
    virObjectUnref(openbsd_driver);
    openbsd_driver = NULL;
    virMutexDestroy(&openbsd_driver_lock);
    //prlsdkDeinit();
    return 0;
}


static int
openbsdStateInitialize(bool privileged ATTRIBUTE_UNUSED,
                  virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                  void *opaque ATTRIBUTE_UNUSED)
{
/*
    if (prlsdkInit() < 0) {
        VIR_DEBUG("%s", _("Can't initialize Parallels SDK"));
        return -1;
    }
*/

   if (virMutexInit(&openbsd_driver_lock) < 0)
        goto error;

    /* Failing to create driver here is not fatal and only means
     * that next driver client will try once more when connecting */
    openbsd_driver = openbsdDriverObjNew();
    return 0;

 error:
    openbsdStateCleanup();
    return -1;
}


static virStateDriver openbsdStateDriver = {
    .name = "openbsd",
    .stateInitialize = openbsdStateInitialize,
    .stateCleanup = openbsdStateCleanup,
};


int openbsdRegister(void)
{
    if (virRegisterConnectDriver(&openbsdConnectDriver, false) < 0)
        return -1;

    if (virRegisterStateDriver(&openbsdStateDriver) < 0)
        return -1;

    return 0;
}
