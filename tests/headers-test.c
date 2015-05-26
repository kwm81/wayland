/*
 * Copyright © 2015 Giulio Camuffo
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include "wayland-client-core.h"
#include "wayland-server-core.h"

#ifdef WL_DISPLAY_SYNC
#error including wayland-client-core.h imported protocol symbols!
#endif
#ifdef WL_DISPLAY_ERROR
#error including wayland-server-core.h imported protocol symbols!
#endif

#ifdef WAYLAND_CLIENT_H
#error including wayland-client-core.h included the non-core header!
#endif
#ifdef WAYLAND_SERVER_H
#error including wayland-server-core.h included the non-core header!
#endif

#include "wayland-client.h"
#include "wayland-server.h"

#ifndef WL_DISPLAY_SYNC
#error including wayland-client.h did not import protocol symbols!
#endif
#ifndef WL_DISPLAY_ERROR
#error including wayland-server.h did not import protocol symbols!
#endif

int main(int argc, char **argv) { return 0; }
