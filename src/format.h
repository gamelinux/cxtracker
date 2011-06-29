/*
** Copyright (C) 2011, Ian Firns <firnsy@securixlive.com>
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifndef __FORMAT_H__
#define __FORMAT_H__

#include <stdio.h>
#include "cxtracker.h"

void format_write(FILE *fd, const connection *cxt);
void format_validate(const char *format);
void format_clear(void);
void format_options(void);

#endif  /* __FORMAT_H__ */
