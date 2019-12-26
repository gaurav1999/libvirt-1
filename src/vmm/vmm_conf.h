/*
 * vmm_conf.h: config information for OpenBSD VMM
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

#pragma once

#include "internal.h"
#include "virdomainobjlist.h"
#include "virthread.h"

#define VMCTL		"/usr/sbin/vmctl"

struct vmm_driver {
    virMutex lock;

    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virDomainObjListPtr domains;
    int version;
};

int vmmLoadDomains(struct openvz_driver *driver);
void vmmFreeDriver(struct openvz_driver *driver);
int strtoI(const char *str);
int vmmSetDefinedUUID(int vpsid, unsigned char *uuid);
int vmmGetVEID(const char *name);
virDomainXMLOptionPtr vmmXMLOption(struct vmm_driver *driver);
