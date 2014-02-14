/*
 * Copyright (c) 2014 Jason Kölker
 *
 */

#include "atheme.h"
#include "uplink.h"

DECLARE_MODULE_V1
(
	"totes/ns_forceuser", false, _modinit, _moddeinit,
	"$Revision: 1 $",
	"Jason Kölker <jason@koelker.net>"
);


static void hook_user_identify(user_t *u);

void _modinit(module_t *m)
{
	hook_add_event("user_identify");
	hook_add_user_identify(hook_user_identify);
}

void _moddeinit(module_unload_intent_t intent)
{
	hook_del_user_identify(hook_user_identify);
}

static void hook_user_identify(user_t *u)
{
	int ret;
	metadata_t *md;
	char *ident;
	char buf[100];

	md = metadata_find(u->myuser, "name");

	if (md != NULL) {
		ident = md->value;
	} else {
		snprintf(buf, 100, "%s_insecure", u->user);
		ident = buf;
	}

	ret = sts("CHGIDENT %s %s", u->uid, ident);
	if (ret == 1) {
		slog(LG_INFO, "Could not set ident (%s) for user (%s): ret (%d)",
		     ident, u->uid, ret);
	}
}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=4
 * vim:sw=4
 * vim:noexpandtab
 */
