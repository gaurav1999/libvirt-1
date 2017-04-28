/*
 * openbsd_driver.c: core driver methods for managing OpenBSD VM's
 *
 * Copyright (C) 2016-2017 Sergey Bronnikov
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
#include "virstring.h"
#include "openbsd_vmm_driver.h"

#include "machine/vmmvar.h"

#define VIR_FROM_THIS VIR_FROM_OPENBSD_VMM

VIR_LOG_INIT("openbsd.openbsd_driver");

struct openbsd_driver obsd_driver;

void openbsdFreeDriver(struct openbsd_driver *driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virObjectUnref(driver->caps);
    VIR_FREE(driver);
}


static virDrvOpenStatus
openbsdConnectOpen(virConnectPtr conn,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   virConfPtr conf ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    struct openbsd_driver *driver;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
                           _("Unexpected OpenBSD URI path '%s', try openbsd:///system"),
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
    if (!(driver->xmlopt = virDomainXMLOptionNew(&openbsdDomainDefParserConfig,
                                                 NULL, NULL)))
        goto cleanup;
    */

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    conn->privateData = NULL;
    virObjectUnref(driver);
    return VIR_DRV_OPEN_ERROR;
};


static int openbsdConnectClose(virConnectPtr conn)
{
    struct openbsd_driver *driver = conn->privateData;

    openbsdFreeDriver(driver);
    conn->privateData = NULL;

    return 0;
}


static virHypervisorDriver openbsdHypervisorDriver = {
    .name = "OPENBSD",
    .connectOpen = openbsdConnectOpen, /* 3.3.0 */
    .connectClose = openbsdConnectClose, /* 3.3.0 */
};


static virConnectDriver openbsdConnectDriver = {
    .hypervisorDriver = &openbsdHypervisorDriver,
};


int openbsdRegister(void)
{
    return virRegisterConnectDriver(&openbsdConnectDriver,
                                    false);
}
