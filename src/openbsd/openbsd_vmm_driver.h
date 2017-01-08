/*
 * openbsd_vmm_driver.h: core driver methods for managing OpenBSD guests
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
 * Author: Sergey Bronnikov <sergeyb@bronevichok.ru>
 */

#ifndef __OPENBSD_VMM_DRIVER_H__
#define __OPENBSD_VMM_DRIVER_H__

#include "internal.h"
#include "virdomainobjlist.h"
#include "virthread.h"

struct openbsd_driver {
    virMutex lock;

    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virDomainObjListPtr domains;
    int version;
};

int openbsdRegister(void);
void openbsdFreeDriver(struct openbsd_driver *driver);

#endif /* __OPENBSD_VMM_DRIVER_H__ */
