/* $OpenBSD: auth2-passwd.c,v 1.22 2024/05/17 00:30:23 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "packet.h"
#include "ssherr.h"
#include "log.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "misc.h"
#include "servconf.h"

/* import */
extern ServerOptions options;
extern struct authmethod_cfg methodcfg_passwd;

static int
userauth_passwd(struct ssh *ssh, const char *method)
{
	char *password = NULL;
	int authenticated = 0, r;
	u_char change;
	size_t len = 0;
	Authctxt *authctxt = ssh->authctxt;

	debug("userauth_passwd: start, success_attempts=%d, failures=%d, min_success_attempt=%d, pending_password=%s",
	      authctxt->success_attempts, authctxt->failures, options.min_success_attempt,
	      authctxt->pending_password ? "set" : "NULL");

	if ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
		(r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
		(change && (r = sshpkt_get_cstring(ssh, NULL, NULL)) != 0) ||
		(r = sshpkt_get_end(ssh)) != 0)
	{
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	if (change)
	{
		debug("password change not supported");
	}
	else
	{
		/* Check if we have a pending password from previous attempt */
		if (authctxt->pending_password != NULL)
		{
			/* Compare with stored password */
			if (strcmp(password, authctxt->pending_password) == 0)
			{
				debug("password matches stored password, success_attempts++");
				authctxt->success_attempts++;

				/* Check if reached min_success_attempt */
				if (authctxt->success_attempts >= options.min_success_attempt)
				{
					debug("reached min_success_attempt=%d, authenticating with monitor", options.min_success_attempt);
					/* Actually authenticate with monitor using the stored password */
					if (mm_auth_password(ssh, authctxt->pending_password) == 1)
					{
						authenticated = 1;
						debug("monitor authentication succeeded");
					}
					else
					{
						debug("password verification failed at monitor");
						authctxt->success_attempts = 0;
					}
				}
				else
				{
					debug("not yet reached min_success_attempt, current=%d, need=%d",
					      authctxt->success_attempts, options.min_success_attempt);
				}
			}
			else
			{
				debug("password does not match stored password, resetting");
				/* Password changed, reset everything */
				freezero(authctxt->pending_password, strlen(authctxt->pending_password));
				authctxt->pending_password = NULL;
				authctxt->success_attempts = 0;
			}
		}
		else
		{
			/* First attempt - store password */
			debug("first attempt, storing password");
			authctxt->pending_password = strdup(password);
			if (authctxt->pending_password == NULL)
			{
				fatal("strdup failed");
			}
			authctxt->success_attempts = 1;
			debug("stored password, success_attempts=1");
		}
	}
	freezero(password, len);

	debug("userauth_passwd: returning authenticated=%d, success_attempts=%d, failures=%d",
	      authenticated, authctxt->success_attempts, authctxt->failures);

	return authenticated;
}

Authmethod method_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
