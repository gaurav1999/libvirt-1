/*
 * openbsd_vmm_driver.h: core driver methods for managing OpenBSD guests
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

#ifndef __OPENBSD_VMM_DRIVER_H__
#define __OPENBSD_VMM_DRIVER_H__

#include "internal.h"
#include "virdomainobjlist.h"
#include "virthread.h"

//struct openbsd_driver {
struct _openbsdDriver {
    virObjectLockable parent;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;
    unsigned char session_uuid[VIR_UUID_BUFLEN];
    //PRL_HANDLE server;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    //virObjectEventStatePtr domainEventState;
    virSysinfoDefPtr hostsysinfo;
    unsigned long openbsdVersion;
    //vzCapabilities vzCaps;
    virMutex lock;
};

typedef struct _openbsdDriver openbsdDriver;
typedef struct _openbsdDriver *openbsdDriverPtr;

struct _openbsdConn {
    struct _openbsdConn* next;

    openbsdDriverPtr driver;
    /* Immutable pointer, self-locking APIs */
    virConnectCloseCallbackDataPtr closeCallback;
};

typedef struct _openbsdConn openbsdConn;
typedef struct _openbsdConn *openbsdConnPtr;

int openbsdRegister(void);
//void openbsdFreeDriver(struct openbsd_driver *driver);

struct _openbsdDomainJobObj {
    virCond cond;
    bool active;
    /* when the job started, zeroed on time discontinuities */
    unsigned long long started;
    unsigned long long elapsed;
    bool hasProgress;
    int progress; /* percents */
    //PRL_HANDLE sdkJob;
    bool cancelled;
};

typedef struct _openbsdDomainJobObj openbsdDomainJobObj;
typedef struct _openbsdDomainJobObj *openbsdDomainJobObjPtr;

struct openbsdDomObj {
    int id;
    //PRL_HANDLE sdkdom;
    //PRL_HANDLE stats;
    openbsdDomainJobObj job;
};

typedef struct openbsdDomObj *openbsdDomObjPtr;

int
vzDomainObjBeginJob(virDomainObjPtr dom);
void
vzDomainObjEndJob(virDomainObjPtr dom);

#endif /* __OPENBSD_VMM_DRIVER_H__ */
