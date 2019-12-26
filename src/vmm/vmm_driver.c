/*
 * vmm_driver.c: core driver methods for managing OpenBSD VMM
 *
 * Copyright (C) 2019 Sergey Bronnikov
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virlog.h"
#include "vircommand.h"
#include "viruri.h"
#include "virnetdevtap.h"
#include "virstring.h"

#include "vmm_conf.h"
#include "vmm_driver.h"
#include "vmm_util.h"

#define VIR_FROM_THIS VIR_FROM_VMM

/* FIXME (sergeyb@) */
VIR_LOG_INIT("openvz.openvz_driver");

static int vmmConnectGetMaxVcpus(virConnectPtr conn, const char *type);
static int openvzDomainSetMemoryInternal(virDomainObjPtr vm,
                                         unsigned long long memory);
static int openvzGetVEStatus(virDomainObjPtr vm, int *status, int *reason);

static void vmmDriverLock(struct vmm_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void vmmDriverUnlock(struct vmm_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

static virDomainObjPtr
vmmDomObjFromDomainLocked(struct vmm_driver *driver,
                             const unsigned char *uuid)
{
    virDomainObjPtr vm;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(vm = virDomainObjListFindByUUID(driver->domains, uuid))) {
        virUUIDFormat(uuid, uuidstr);

        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        return NULL;
    }

    return vm;
}


static virDomainObjPtr
vmmDomObjFromDomain(struct vmm_driver *driver,
                       const unsigned char *uuid)
{
    virDomainObjPtr vm;

    vmmDriverLock(driver);
    vm = vmmDomObjFromDomainLocked(driver, uuid);
    vmmDriverUnlock(driver);
    return vm;
}


static virCommandPtr
openvzDomainDefineCmd(virDomainDefPtr vmdef)
{
    virCommandPtr cmd = virCommandNewArgList(VZCTL,
                                             "--quiet",
                                             "create",
                                             NULL);

    if (vmdef == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container is not defined"));
        virCommandFree(cmd);
        return NULL;
    }

    virCommandAddArgList(cmd, vmdef->name, "--name", vmdef->name, NULL);

    return cmd;
}


static int vmmSetInitialConfig(virDomainDefPtr vmdef)
{
    return 0;
}


static char *
vmmDomainGetHostname(virDomainPtr dom, unsigned int flags)
{
    char *hostname = NULL;
    /* TODO (sergeyb@) */

    return hostname;
}


static virDomainPtr vmmDomainLookupByID(virConnectPtr conn,
                                           int id)
{
    struct vmm_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmmDriverLock(driver);
    vm = virDomainObjListFindByID(driver->domains, id);
    vmmDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id '%d'"), id);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int vmmConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct utsname ver;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    uname(&ver);

    if (virParseVersionString(ver.release, version, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown release: %s"), ver.release);
        return -1;
    }

    return 0;
}


static char *vmmConnectGetHostname(virConnectPtr conn G_GNUC_UNUSED)
{
    return virGetHostname();
}


static char *vmmDomainGetOSType(virDomainPtr dom)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

    virDomainObjEndAPI(&vm);
    return ret;
}


static virDomainPtr vmmDomainLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid)
{
    struct  vmm_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    if (!(vm = vmmDomObjFromDomain(driver, uuid)))
        return NULL;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

    virDomainObjEndAPI(&vm);

    return dom;
}

static virDomainPtr vmmDomainLookupByName(virConnectPtr conn,
                                             const char *name)
{
    struct vmm_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmmDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, name);
    vmmDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int vmmDomainGetInfo(virDomainPtr dom,
                               virDomainInfoPtr info)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int state;
    int ret = -1;

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &state, NULL) == -1)
        goto cleanup;
    info->state = state;

    if (info->state != VIR_DOMAIN_RUNNING) {
        info->cpuTime = 0;
    } else {
        /* FIXME: (sergeyb@) */
        info->cpuTime = 100;
    }

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
openvzDomainGetState(virDomainPtr dom,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = vmmGetVEStatus(vm, state, reason);

    virDomainObjEndAPI(&vm);

    return ret;
}


static int vmmDomainIsActive(virDomainPtr dom)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = virDomainObjIsActive(obj);

    virDomainObjEndAPI(&obj);

    return ret;
}


static int vmmDomainIsPersistent(virDomainPtr dom)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = obj->persistent;

    virDomainObjEndAPI(&obj);
    return ret;
}

static int vmmDomainIsUpdated(virDomainPtr dom G_GNUC_UNUSED)
{
    return 0;
}

static char *vmmDomainGetXMLDesc(virDomainPtr dom, unsigned int flags) {
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return NULL;

    ret = virDomainDefFormat(vm->def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

    virDomainObjEndAPI(&vm);
    return ret;
}


/*
 * Convenient helper to target a command line argv
 * and fill in an empty slot with the supplied
 * key value. This lets us declare the argv on the
 * stack and just splice in the domain name after
 */
#define PROGRAM_SENTINEL ((char *)0x1)
static void openvzSetProgramSentinal(const char **prog, const char *key)
{
    const char **tmp = prog;
    while (tmp && *tmp) {
        if (*tmp == PROGRAM_SENTINEL) {
            *tmp = key;
            break;
        }
        tmp++;
    }
}

static int
vmmDomainShutdownFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VMCTL, "stop", PROGRAM_SENTINEL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
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
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
vmmDomainShutdown(virDomainPtr dom)
{
    return vmmDomainShutdownFlags(dom, 0);
}

static int
vmmDomainDestroy(virDomainPtr dom)
{
    return vmmDomainShutdownFlags(dom, 0);
}

static int
vmmDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    return vmmDomainShutdownFlags(dom, flags);
}

static int vmmDomainReboot(virDomainPtr dom,
                              unsigned int flags)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VMCTL, "reset", PROGRAM_SENTINEL, NULL};
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    if (!(vm = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    openvzSetProgramSentinal(prog, vm->def->name);
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
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
openvzDomainSetNetwork(virConnectPtr conn, const char *vpsid,
                       virDomainNetDefPtr net,
                       virBufferPtr configBuf)
{
    int rc = -1;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virMacAddr host_mac;
    char host_macaddr[VIR_MAC_STRING_BUFLEN];
    struct openvz_driver *driver =  conn->privateData;
    virCommandPtr cmd = NULL;
    char *guest_ifname = NULL;

    if (net == NULL)
        return 0;

    if (vpsid == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Container ID is not specified"));
        return -1;
    }

    if (net->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET)
        return 0;

    cmd = virCommandNewArgList(VZCTL, "--quiet", "set", vpsid, NULL);

    virMacAddrFormat(&net->mac, macaddr);
    virDomainNetGenerateMAC(driver->xmlopt, &host_mac);
    virMacAddrFormat(&host_mac, host_macaddr);

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
         net->guestIP.nips == 0)) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        int veid = openvzGetVEID(vpsid);

        virBufferAdd(&buf, guest_ifname, -1); /* Guest dev */
        virBufferAsprintf(&buf, ",%s", macaddr); /* Guest dev mac */
        virBufferAsprintf(&buf, ",%s", net->ifname); /* Host dev */
        virBufferAsprintf(&buf, ",%s", host_macaddr); /* Host dev mac */

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (driver->version >= VZCTL_BRIDGE_MIN_VERSION) {
                virBufferAsprintf(&buf, ",%s", net->data.bridge.brname); /* Host bridge */
            } else {
                virBufferAsprintf(configBuf, "ifname=%s", guest_ifname);
                virBufferAsprintf(configBuf, ",mac=%s", macaddr); /* Guest dev mac */
                virBufferAsprintf(configBuf, ",host_ifname=%s", net->ifname); /* Host dev */
                virBufferAsprintf(configBuf, ",host_mac=%s", host_macaddr); /* Host dev mac */
                virBufferAsprintf(configBuf, ",bridge=%s", net->data.bridge.brname); /* Host bridge */
            }
        }

        /* --netif_add ifname[,mac,host_ifname,host_mac] */
        virCommandAddArg(cmd, "--netif_add");
        virCommandAddArgBuffer(cmd, &buf);
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
               net->guestIP.nips > 0) {
        size_t i;

        /* --ipadd ip */
        for (i = 0; i < net->guestIP.nips; i++) {
            char *ipStr = virSocketAddrFormat(&net->guestIP.ips[i]->address);
            if (!ipStr)
                goto cleanup;
            virCommandAddArgList(cmd, "--ipadd", ipStr, NULL);
            VIR_FREE(ipStr);
        }
    }

    /* TODO: processing NAT and physical device */

    virCommandAddArg(cmd, "--save");
    rc = virCommandRun(cmd, NULL);

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(guest_ifname);
    return rc;
}


static virDomainPtr
vmmDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    /* TODO (sergeyb@) */
    struct vmm_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    vmmDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", vmdef->name, "\n") < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, vmdef,
                                   driver->xmlopt,
                                   0, NULL)))
        goto cleanup;
    vmdef = NULL;
    vm->persistent = 1;

    if (vmmSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    if (virDomainDefHasVcpusOffline(vm->def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpu count must equal maximum"));
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, -1);

 cleanup:
    virDomainDefFree(vmdef);
    virDomainObjEndAPI(&vm);
    openvzDriverUnlock(driver);
    return dom;
}

static virDomainPtr
vmmDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return vmmDomainDefineXMLFlags(conn, xml, 0);
}

static virDomainPtr
vmmDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    struct vmm_driver *driver =  conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    /* vmctl create -s 4.5G disk.img */
    /* vmctl start -m 1G -i 1 -b /bsd -d disk.img "myvm" */
    const char *progstart[] = {VMCTL, "create", "-i", PROGRAM_SENTINEL, NULL};
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    vmmDriverLock(driver);
    if ((vmdef = virDomainDefParseString(xml, driver->xmlopt,
                                         NULL, parse_flags)) == NULL)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains,
                                   vmdef,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    vmdef = NULL;
    /* All OpenVZ domains seem to be persistent - this is a bit of a violation
     * of this libvirt API which is intended for transient domain creation */
    vm->persistent = 1;

    if (vmmSetInitialConfig(vm->def) < 0) {
        VIR_ERROR(_("Error creating initial configuration"));
        goto cleanup;
    }

    if (openvzSetDefinedUUID(strtoI(vm->def->name), vm->def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not set UUID"));
        goto cleanup;
    }

    openvzSetProgramSentinal(progstart, vm->def->name);

    if (virRun(progstart, NULL) < 0)
        goto cleanup;

    vm->pid = strtoI(vm->def->name);
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainDefFree(vmdef);
    virDomainObjEndAPI(&vm);
    vmmDriverUnlock(driver);
    return dom;
}

static int
openvzDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    struct openvz_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    const char *prog[] = {VMCTL, "start", PROGRAM_SENTINEL, NULL };
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    openvzDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, dom->name);
    openvzDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), dom->name);
        goto cleanup;
    }

    if (openvzGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    if (status != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("domain is not in shutoff state"));
        goto cleanup;
    }

    openvzSetProgramSentinal(prog, vm->def->name);
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

static int
vmmDomainCreate(virDomainPtr dom)
{
    return vmmDomainCreateWithFlags(dom, 0);
}

static int
vmmDomainUndefineFlags(virDomainPtr dom,
                          unsigned int flags)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int status;

    virCheckFlags(0, -1);

    vmmDriverLock(driver);
    if (!(vm = vmmDomObjFromDomainLocked(driver, dom->uuid)))
        goto cleanup;

    if (vmmGetVEStatus(vm, &status, NULL) == -1)
        goto cleanup;

    /* TODO: vmctl doesn't support destroy */
    if (virRun(prog, NULL) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    vmmDriverUnlock(driver);
    return ret;
}

static int
vmmDomainUndefine(virDomainPtr dom)
{
    return vmmDomainUndefineFlags(dom, 0);
}

static int
vmmConnectURIProbe(char **uri)
{
    *uri = g_strdup("openbsd:///system");

    return 1;
}


static virDrvOpenStatus vmmConnectOpen(virConnectPtr conn,
                                          virConnectAuthPtr auth G_GNUC_UNUSED,
                                          virConfPtr conf G_GNUC_UNUSED,
                                          unsigned int flags)
{
    struct vmm_driver *driver;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* TODO: check openbsd version? */

    /* TODO: check existance of /var/run/vmd.sock */
    /*
    if (access("/var/run/vmd.sock", W_OK) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("OpenBSD VMM control UNIX-domain socket used for
                        communication with vmd(8) is not accessible"));
        return VIR_DRV_OPEN_ERROR;
    }
    */

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (VIR_ALLOC(driver) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (!(driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(driver->caps = vmmCapsInit()))
        goto cleanup;

    if (!(driver->xmlopt = vmmXMLOption(driver)))
        goto cleanup;

    if (vmmLoadDomains(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    vmmFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int vmmConnectClose(virConnectPtr conn)
{
    struct vmm_driver *driver = conn->privateData;

    vmmFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}

static const char *vmmConnectGetType(virConnectPtr conn G_GNUC_UNUSED) {
    return "OpenBSD VMM";
}

static int vmmConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}

static int vmmConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static int
vmmConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static char *vmmConnectGetCapabilities(virConnectPtr conn) {
    struct vmm_driver *driver = conn->privateData;
    char *ret;

    vmmDriverLock(driver);
    ret = virCapabilitiesFormatXML(driver->caps);
    vmmDriverUnlock(driver);

    return ret;
}

/* TODO (sergeyb@) */
static int vmmConnectListDomains(virConnectPtr conn G_GNUC_UNUSED,
                                    int *ids, int nids)
{
    int got = 0;
    int veid;
    int outfd = -1;
    int rc = -1;
    int ret;
    char buf[32];
    char *endptr;
    virCommandPtr cmd = virCommandNewArgList(VMCTL, "status", NULL);

    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto cleanup;

    while (got < nids) {
        ret = openvz_readline(outfd, buf, 32);
        if (!ret)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %s"), buf);
            continue;
        }
        ids[got] = veid;
        got ++;
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        goto cleanup;
    }

    rc = got;
 cleanup:
    VIR_FORCE_CLOSE(outfd);
    virCommandFree(cmd);
    return rc;
}

static int vmmConnectNumOfDomains(virConnectPtr conn)
{
    struct vmm_driver *driver = conn->privateData;
    int n = 0;

    vmmDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, true, NULL, NULL);
    vmmDriverUnlock(driver);

    return n;
}

static int vmmConnectListDefinedDomains(virConnectPtr conn G_GNUC_UNUSED,
                                           char **const names, int nnames) {
    int got = 0;
    int veid, outfd = -1, ret;
    int rc = -1;
    char vpsname[32];
    char buf[32];
    char *endptr;
    virCommandPtr cmd = virCommandNewArgList(VZLIST,
                                             "-ovpsid", "-H", "-S", NULL);

    /* the -S options lists only stopped domains */
    virCommandSetOutputFD(cmd, &outfd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto out;

    while (got < nnames) {
        ret = openvz_readline(outfd, buf, 32);
        if (!ret)
            break;
        if (virStrToLong_i(buf, &endptr, 10, &veid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not parse VPS ID %s"), buf);
            continue;
        }
        g_snprintf(vpsname, sizeof(vpsname), "%d", veid);
        names[got] = g_strdup(vpsname);
        got ++;
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto out;

    if (VIR_CLOSE(outfd) < 0) {
        virReportSystemError(errno, "%s", _("failed to close file"));
        goto out;
    }

    rc = got;
 out:
    VIR_FORCE_CLOSE(outfd);
    virCommandFree(cmd);
    if (rc < 0) {
        for (; got >= 0; got--)
            VIR_FREE(names[got]);
    }
    return rc;
}


static int vmmConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct vmm_driver *driver =  conn->privateData;
    int n = 0;

    vmmDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, false, NULL, NULL);
    vmmDriverUnlock(driver);

    return n;
}


static int
vmmDomainGetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int *nparams,
                                unsigned int flags)
{
    /* TODO: (sergeyb@) */
    result = 0;

    return result;
}


static int
vmmDomainSetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    /* TODO: (sergeyb@) */
    result = 0;

    return result;
}


static int
openvzGetVEStatus(virDomainObjPtr vm, int *status, int *reason)
{
    virCommandPtr cmd;
    char *outbuf;
    char *line;
    int state;
    int ret = -1;

    cmd = virCommandNewArgList(VZLIST, vm->def->name, "-ostatus", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if ((line = strchr(outbuf, '\n')) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to parse vzlist output"));
        goto cleanup;
    }
    *line++ = '\0';

    state = virDomainObjGetState(vm, reason);

    if (STREQ(outbuf, "running")) {
        /* There is no way to detect whether a domain is paused or not
         * with vzlist */
        if (state == VIR_DOMAIN_PAUSED)
            *status = state;
        else
            *status = VIR_DOMAIN_RUNNING;
    } else {
        *status = VIR_DOMAIN_SHUTOFF;
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    return ret;
}

static int
vmmDomainInterfaceStats(virDomainPtr dom,
                           const char *device,
                           virDomainInterfaceStatsPtr stats)
{
    return 0;
}

static int
vmmConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    struct vmm_driver *driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    vmmDriverLock(driver);
    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 NULL, flags);
    vmmDriverUnlock(driver);

    return ret;
}


static int
vmmNodeGetInfo(virConnectPtr conn G_GNUC_UNUSED,
                  virNodeInfoPtr nodeinfo)
{
    return virCapabilitiesGetNodeInfo(nodeinfo);
}


static int
vmmNodeGetCPUStats(virConnectPtr conn G_GNUC_UNUSED,
                      int cpuNum,
                      virNodeCPUStatsPtr params,
                      int *nparams,
                      unsigned int flags)
{
    return virHostCPUGetStats(cpuNum, params, nparams, flags);
}


static int
vmmNodeGetMemoryStats(virConnectPtr conn G_GNUC_UNUSED,
                         int cellNum,
                         virNodeMemoryStatsPtr params,
                         int *nparams,
                         unsigned int flags)
{
    return virHostMemGetStats(cellNum, params, nparams, flags);
}


static int
vmmNodeGetCellsFreeMemory(virConnectPtr conn G_GNUC_UNUSED,
                             unsigned long long *freeMems,
                             int startCell,
                             int maxCells)
{
    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}


static unsigned long long
vmmNodeGetFreeMemory(virConnectPtr conn G_GNUC_UNUSED)
{
    unsigned long long freeMem;
    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;
    return freeMem;
}


static int
vmmNodeGetCPUMap(virConnectPtr conn G_GNUC_UNUSED,
                    unsigned char **cpumap,
                    unsigned int *online,
                    unsigned int flags)
{
    return virHostCPUGetMap(cpumap, online, flags);
}


static int
vmmConnectSupportsFeature(virConnectPtr conn G_GNUC_UNUSED, int feature)
{
    switch ((virDrvFeature) feature) {
    case VIR_DRV_FEATURE_FD_PASSING:
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    case VIR_DRV_FEATURE_REMOTE:
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    default:
        return 0;
    }
}


static int
vmmDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    struct vmm_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = vmmDomObjFromDomain(driver, dom->uuid)))
        return -1;

    ret = 0;

    virDomainObjEndAPI(&obj);
    return ret;
}



static virHypervisorDriver vmmHypervisorDriver = {
    .name = "OpenBSD VMM",
    .connectURIProbe = vmmConnectURIProbe,
    .connectOpen = vmmConnectOpen, /* 0.3.1 */
    .connectClose = vmmConnectClose, /* 0.3.1 */
    .connectGetType = vmmConnectGetType, /* 0.3.1 */
    .connectGetVersion = vmmConnectGetVersion, /* 0.5.0 */
    .connectGetHostname = vmmConnectGetHostname, /* 0.9.12 */
    .nodeGetInfo = vmmNodeGetInfo, /* 0.3.2 */
    .nodeGetCPUStats = vmmNodeGetCPUStats, /* 0.9.12 */
    .nodeGetMemoryStats = vmmNodeGetMemoryStats, /* 0.9.12 */
    .nodeGetCellsFreeMemory = vmmNodeGetCellsFreeMemory, /* 0.9.12 */
    .nodeGetFreeMemory = vmmNodeGetFreeMemory, /* 0.9.12 */
    .nodeGetCPUMap = vmmNodeGetCPUMap, /* 1.0.0 */
    .connectGetCapabilities = vmmConnectGetCapabilities, /* 0.4.6 */
    .connectListDomains = vmmConnectListDomains, /* 0.3.1 */
    .connectNumOfDomains = vmmConnectNumOfDomains, /* 0.3.1 */
    .connectListAllDomains = vmmConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = openvzDomainCreateXML, /* 0.3.3 */
    .domainLookupByID = vmmDomainLookupByID, /* 0.3.1 */
    .domainLookupByUUID = vmmDomainLookupByUUID, /* 0.3.1 */
    .domainLookupByName = vmmDomainLookupByName, /* 0.3.1 */
    .domainShutdown = vmmDomainShutdown, /* 0.3.1 */
    .domainShutdownFlags = vmmDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = vmmDomainReboot, /* 0.3.1 */
    .domainDestroy = openvzDomainDestroy, /* 0.3.1 */
    .domainDestroyFlags = openvzDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = openvzDomainGetOSType, /* 0.3.1 */
    .domainGetMemoryParameters = vmmDomainGetMemoryParameters, /* 0.9.12 */
    .domainSetMemoryParameters = vmmDomainSetMemoryParameters, /* 0.9.12 */
    .domainGetInfo = vmmDomainGetInfo, /* 0.3.1 */
    .domainGetState = openvzDomainGetState, /* 0.9.2 */
    .domainGetVcpusFlags = openvzDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetXMLDesc = openvzDomainGetXMLDesc, /* 0.4.6 */
    .connectListDefinedDomains = openvzConnectListDefinedDomains, /* 0.3.1 */
    .connectNumOfDefinedDomains = vmmConnectNumOfDefinedDomains, /* 0.3.1 */
    .domainCreate = vmmDomainCreate, /* 0.3.1 */
    .domainCreateWithFlags = vmmDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = vmmDomainDefineXML, /* 0.3.3 */
    .domainDefineXMLFlags = vmmDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = vmmDomainUndefine, /* 0.3.3 */
    .domainUndefineFlags = vmmDomainUndefineFlags, /* 0.9.4 */
    .domainInterfaceStats = vmmDomainInterfaceStats, /* 0.9.12 */
    .connectIsEncrypted = vmmConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = vmmConnectIsSecure, /* 0.7.3 */
    .domainIsActive = vmmDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = openvzDomainIsPersistent,
    .domainIsUpdated = vmmDomainIsUpdated, /* 0.8.6 */
    .connectIsAlive = vmmConnectIsAlive, /* 0.9.8 */
    .domainGetHostname = vmmDomainGetHostname, /* 0.10.0 */
    .connectSupportsFeature = vmmConnectSupportsFeature, /* 1.2.8 */
    .domainHasManagedSaveImage = vmmDomainHasManagedSaveImage, /* 1.2.13 */
};

static virConnectDriver vmmConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "vmm", NULL },
    .hypervisorDriver = &vmmHypervisorDriver,
};

int vmmRegister(void)
{
    return virRegisterConnectDriver(&vmmConnectDriver,
                                    false);
}
