/*
 * Copyright (c) 2014 Kevin Mancuso
 * Rights to this code are as documented in doc/LICENSE.
 *
 * USAGE: fpass <account> <pass> [PLAIN|CRYPT]
 * PLAIN uses built in set_password and will use default crypt
 * CRYPT sets the password specific assuming pre-encrypted
 *
 * Disclaimer: I have no idea what I'm doing, lol
 */

#include "atheme.h"

DECLARE_MODULE_V1
(
    "totes/ns_fpass", false, _modinit, _moddeinit,
    PACKAGE_STRING,
    "Atheme Development Group <http://www.atheme.org>"
);

static void ns_cmd_fpass(sourceinfo_t *si, int parc, char *parv[]);

command_t ns_fpass = { "FPASS", "Sets a precypted password on behalf of another user.", PRIV_USER_ADMIN, 3, ns_cmd_fpass, { .path = "totes/fpass" } };

void _modinit(module_t *m)
{
    service_named_bind_command("nickserv", &ns_fpass);
}

void _moddeinit(module_unload_intent_t intent)
{
    service_named_unbind_command("nickserv", &ns_fpass);
}

static void ns_cmd_fpass(sourceinfo_t *si, int parc, char *parv[])
{

    char *target = parv[0];
    char *password = parv[1];
    char *crypt = parv[2];

    myuser_t *mu = si->smu;

    if (!target || !password || !crypt)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FPASS");
        command_fail(si, fault_needmoreparams, "Syntax: FPASS <account> <pass> [PLAIN|CRYPT]");
        return;
    }

    if (auth_module_loaded)
    {
        command_fail(si, fault_noprivs, _("You must change the password in the external system."));
        return;
    }

    if (!(mu = myuser_find(target)))
    {
        command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
        return;
    }

    if (!strcasecmp(crypt, "CRYPT"))
    {
        logcommand(si, CMDLOG_SET, "FPASS: \2%s\2 CRYPTED", entity(mu)->name);
        mowgli_strlcpy(mu->pass, password, PASSLEN);
    }
    else if (!strcasecmp(crypt, "PLAIN"))
    {
        if (strlen(password) >= PASSLEN)
        {
            command_fail(si, fault_badparams, STR_INVALID_PARAMS, "FPASS");
            command_fail(si, fault_badparams, _("Passwords can not exceed \2%d\2 characters."), PASSLEN - 1);
            return;
        }
        else
        {
            logcommand(si, CMDLOG_SET, "FPASS: \2%s\2", entity(mu)->name);
            set_password(mu, password);
        }
    }
    else
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FPASS");
        command_fail(si, fault_needmoreparams, "Syntax: FPASS <account> <pass> [PLAIN|CRYPT]");
        return;
    }
    command_success_nodata(si, _("The password for \2%s\2 has been changed to \2%s\2."), entity(mu)->name, password);
    return;

}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=4
 * vim:sw=4
 * vim:noexpandtab
 */
