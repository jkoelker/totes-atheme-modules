/*
 * Copyright (c) 2014 Jason Kölker
 *
 */

#include "atheme.h"
#include "uplink.h"

DECLARE_MODULE_V1
(
	"contrib/rs_forcegecos", false, _modinit, _moddeinit,
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
	char *realname;

	md = metadata_find(u->myuser, "realname");

	if (md != NULL) {
		realname = md->value;
	} else {
		realname = "LOL I'm insecure";
	}

	ret = sts("CHGNAME %s :%s", u->uid, realname);
	if (ret == 1) {
		slog(LG_INFO, "Could not set realname (%s) for user (%s): ret (%d)",
		     realname, u->uid, ret);
	}
}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=4
 * vim:sw=4
 * vim:noexpandtab
 */
