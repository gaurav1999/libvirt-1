/*
 * vmm_conf.c: config functions for managing OpenBSD VMM
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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "virerror.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"
#include "virhostcpu.h"

#include "vmm_conf.h"
#include "vmm_util.h"

#define VIR_FROM_THIS VIR_FROM_VMM

static int openvzGetVPSUUID(int vpsid, char *uuidstr, size_t len);
static int openvzAssignUUIDs(void);

int
strtoI(const char *str)
{
    int val;

    if (virStrToLong_i(str, NULL, 10, &val) < 0)
        return 0;

    return val;
}


virCapsPtr vmmCapsInit(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    if (virCapabilitiesInitCaches(caps) < 0)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_HVM,
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        return NULL;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_VMM,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        return NULL;

    return g_steal_pointer(&caps);
}


/* Free all memory associated with a vmm_driver structure */
void
vmmFreeDriver(struct vmm_driver *driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->caps);
    VIR_FREE(driver);
}


int vmmLoadDomains(struct vmm_driver *driver)
{
    int veid, ret;
    char *status;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr dom = NULL;
    virDomainDefPtr def = NULL;
    char *temp = NULL;
    char *outbuf = NULL;
    char *line;
    virCommandPtr cmd = NULL;
    unsigned int vcpus = 0;

    if (openvzAssignUUIDs() < 0)
        return -1;

    cmd = virCommandNewArgList(VMCTL, "-a", "-ovpsid,status", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    line = outbuf;
    while (line[0] != '\0') {
        unsigned int flags = 0;
        if (virStrToLong_i(line, &status, 10, &veid) < 0 ||
            *status++ != ' ' ||
            (line = strchr(status, '\n')) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to parse vzlist output"));
            goto cleanup;
        }
        *line++ = '\0';

        if (!(def = virDomainDefNew()))
            goto cleanup;

        def->virtType = VIR_DOMAIN_VIRT_OPENVZ;

        if (STREQ(status, "stopped"))
            def->id = -1;
        else
            def->id = veid;
        def->name = g_strdup_printf("%i", veid);

        openvzGetVPSUUID(veid, uuidstr, sizeof(uuidstr));
        ret = virUUIDParse(uuidstr, def->uuid);

        if (ret == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("UUID in config file malformed"));
            goto cleanup;
        }

        def->os.type = VIR_DOMAIN_OSTYPE_EXE;
        def->os.init = g_strdup("/sbin/init");

        ret = openvzReadVPSConfigParam(veid, "CPUS", &temp);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read config for container %d"),
                           veid);
            goto cleanup;
        } else if (ret > 0) {
            vcpus = strtoI(temp);
        }

        if (ret == 0 || vcpus == 0)
            vcpus = virHostCPUGetCount();

        if (virDomainDefSetVcpusMax(def, vcpus, driver->xmlopt) < 0)
            goto cleanup;

        if (virDomainDefSetVcpus(def, vcpus) < 0)
            goto cleanup;

        /* XXX load rest of VM config data .... */

        openvzReadNetworkConf(def, veid);
        openvzReadFSConf(def, veid);
        openvzReadMemConf(def, veid);

        virUUIDFormat(def->uuid, uuidstr);
        flags = VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE;
        if (STRNEQ(status, "stopped"))
            flags |= VIR_DOMAIN_OBJ_LIST_ADD_LIVE;

        if (!(dom = virDomainObjListAdd(driver->domains,
                                        def,
                                        driver->xmlopt,
                                        flags,
                                        NULL)))
            goto cleanup;

        if (STREQ(status, "stopped")) {
            virDomainObjSetState(dom, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_UNKNOWN);
            dom->pid = -1;
        } else {
            virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNKNOWN);
            dom->pid = veid;
        }
        /* XXX OpenVZ doesn't appear to have concept of a transient domain */
        dom->persistent = 1;

        virDomainObjEndAPI(&dom);
        dom = NULL;
        def = NULL;
    }

    virCommandFree(cmd);
    VIR_FREE(temp);
    VIR_FREE(outbuf);

    return 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(temp);
    VIR_FREE(outbuf);
    virDomainDefFree(def);
    return -1;
}

static int
openvzGetVPSUUID(int vpsid, char *uuidstr, size_t len)
{
    char *conf_file;
    char *line = NULL;
    size_t line_size = 0;
    char *saveptr = NULL;
    char *uuidbuf;
    char *iden;
    FILE *fp;
    int retval = -1;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    fp = fopen(conf_file, "r");
    if (fp == NULL)
        goto cleanup;

    while (1) {
        if (getline(&line, &line_size, fp) < 0) {
            if (feof(fp)) { /* EOF, UUID was not found */
                uuidstr[0] = 0;
                break;
            } else {
                goto cleanup;
            }
        }

        iden = strtok_r(line, " ", &saveptr);
        uuidbuf = strtok_r(NULL, "\n", &saveptr);

        if (iden != NULL && uuidbuf != NULL && STREQ(iden, "#UUID:")) {
            if (virStrcpy(uuidstr, uuidbuf, len) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid uuid %s"), uuidbuf);
                goto cleanup;
            }
            break;
        }
    }
    retval = 0;
 cleanup:
    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
    VIR_FREE(conf_file);

    return retval;
}

int
openvzSetDefinedUUID(int vpsid, unsigned char *uuid)
{
    char *conf_file;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    FILE *fp = NULL;
    int ret = -1;

    if (uuid == NULL)
        return -1;

    if (openvzLocateConfFile(vpsid, &conf_file, "conf") < 0)
        return -1;

    if (openvzGetVPSUUID(vpsid, uuidstr, sizeof(uuidstr)))
        goto cleanup;

    if (uuidstr[0] == 0) {
        fp = fopen(conf_file, "a"); /* append */
        if (fp == NULL)
            goto cleanup;

        virUUIDFormat(uuid, uuidstr);

        /* Record failure if fprintf or VIR_FCLOSE fails,
           and be careful always to close the stream.  */
        if ((fprintf(fp, "\n#UUID: %s\n", uuidstr) < 0) ||
            (VIR_FCLOSE(fp) == EOF))
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_FCLOSE(fp);
    VIR_FREE(conf_file);
    return ret;
}

static int
openvzSetUUID(int vpsid)
{
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDGenerate(uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to generate UUID"));
        return -1;
    }

    return openvzSetDefinedUUID(vpsid, uuid);
}

/*
 * Scan VPS config files and see if they have a UUID.
 * If not, assign one. Just append one to the config
 * file as comment so that the OpenVZ tools ignore it.
 *
 */

static int openvzAssignUUIDs(void)
{
    DIR *dp;
    struct dirent *dent;
    char *conf_dir;
    int vpsid;
    char *ext;
    int ret = 0;

    conf_dir = openvzLocateConfDir();
    if (conf_dir == NULL)
        return -1;

    if (virDirOpenQuiet(&dp, conf_dir) < 0) {
        VIR_FREE(conf_dir);
        return 0;
    }

    while ((ret = virDirRead(dp, &dent, conf_dir)) > 0) {
        if (virStrToLong_i(dent->d_name, &ext, 10, &vpsid) < 0 ||
            *ext++ != '.' ||
            STRNEQ(ext, "conf"))
            continue;
        if (vpsid > 0) /* '0.conf' belongs to the host, ignore it */
            openvzSetUUID(vpsid);
    }

    VIR_DIR_CLOSE(dp);
    VIR_FREE(conf_dir);
    return ret;
}


int vmmGetVEID(const char *name)
{
    virCommandPtr cmd;
    char *outbuf;
    char *temp;
    int veid;
    bool ok;

    cmd = virCommandNewArgList(VMCTL, name, "-ovpsid", "-H", NULL);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0) {
        virCommandFree(cmd);
        VIR_FREE(outbuf);
        return -1;
    }

    virCommandFree(cmd);
    ok = virStrToLong_i(outbuf, &temp, 10, &veid) == 0 && *temp == '\n';
    VIR_FREE(outbuf);

    if (ok && veid >= 0)
        return veid;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Failed to parse vzlist output"));
    return -1;
}


static int
vmmDomainDefPostParse(virDomainDefPtr def,
                         unsigned int parseFlags G_GNUC_UNUSED,
                         void *opaque,
                         void *parseOpaque G_GNUC_UNUSED)
{
    /*
    TODO: sergeyb@
    
    struct openvz_driver *driver = opaque;
    if (!virCapabilitiesDomainSupported(driver->caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE && !def->os.init)
        def->os.init = g_strdup("/sbin/init");
    */

    return 0;
}


static int
vmmDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                               const virDomainDef *def G_GNUC_UNUSED,
                               unsigned int parseFlags G_GNUC_UNUSED,
                               void *opaque G_GNUC_UNUSED,
                               void *parseOpaque G_GNUC_UNUSED)
{
    /*
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not "
                         "supported in %s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }
    */

    return 0;
}


virDomainDefParserConfig vmmDomainDefParserConfig = {
    .domainPostParseCallback = vmmDomainDefPostParse,
    .devicesPostParseCallback = vmmDomainDeviceDefPostParse,
    .features = VIR_DOMAIN_DEF_FEATURE_NAME_SLASH,
};

virDomainXMLOptionPtr vmmXMLOption(struct vmm_driver *driver)
{
    vmmDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&vmmDomainDefParserConfig,
                                 NULL, NULL, NULL, NULL);
}
