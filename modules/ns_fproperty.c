/*
 * Copyright (c) 2014 Kevin Mancuso
 *
 * Ineptly Modified set_property.c
 * Copyright (c) 2005 William Pitcock <nenolod -at- nenolod.net>
 * Copyright (c) 2007 Jilles Tjoelker
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Manipulates metadata entries associated with an account.
 *
 * FRPOPERTY <account> <property> [value]
 *
 * LOL I have no idea what im doing.
 */

#include "atheme.h"

DECLARE_MODULE_V1
(
    "totes/ns_fproperty", false, _modinit, _moddeinit,
    PACKAGE_STRING,
    "Atheme Development Group <http://www.atheme.org>"
);

static void ns_cmd_fproperty(sourceinfo_t *si, int parc, char *parv[]);

command_t ns_fproperty = { "FPROPERTY", "Set metadata on behalf of another user.", PRIV_USER_ADMIN, 3, ns_cmd_fproperty, { .path = "totes/fproperty" } };

void _modinit(module_t *m)
{
    service_named_bind_command("nickserv", &ns_fproperty);
}

void _moddeinit(module_unload_intent_t intent)
{
    service_named_unbind_command("nickserv", &ns_fproperty);
}


/* SET PROPERTY <account> <property> [value] */
static void ns_cmd_fproperty(sourceinfo_t *si, int parc, char *parv[])
{
    char *target = parv[0];
    char *property = parv[1];
    char *value = strtok(parv[2], "");
    unsigned int count;
    mowgli_patricia_iteration_state_t state;
    metadata_t *md;
    hook_metadata_change_t mdchange;
    myuser_t *mu;

    if (!target || !property)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FPROPERTY");
        command_fail(si, fault_needmoreparams, _("Syntax: FPROPERTY <target> <property>: [value]"));
        return;
    }

    if (!(mu = myuser_find(target)))
    {
        command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
        return;
    }

    if (strchr(property, ':') && !has_priv(si, PRIV_METADATA))
    {
        command_fail(si, fault_badparams, _("Invalid property name."));
        return;
    }

    if (strchr(property, ':'))
        logcommand(si, CMDLOG_SET, "FPROPERTY: \2%s\2: \2%s\2/\2%s\2", entity(mu)->name, property, value);

    if (!value)
    {
        md = metadata_find(mu, property);

        if (!md)
        {
            command_fail(si, fault_nosuch_target, _("Metadata entry \2%s\2 was not set."), property);
            return;
        }

        mdchange.target = mu;
        mdchange.name = md->name;
        mdchange.value = md->value;
        hook_call_metadata_change(&mdchange);

        metadata_delete(mu, property);
        logcommand(si, CMDLOG_SET, "FPROPERTY: \2%s\2 (deleted)", property);
        command_success_nodata(si, _("Metadata entry \2%s\2 has been deleted."), property);
        return;
    }

    count = 0;
    MOWGLI_PATRICIA_FOREACH(md, &state, object(mu)->metadata)
    {
        if (strncmp(md->name, "private:", 8))
            count++;
    }
    if (count >= me.mdlimit)
    {
        command_fail(si, fault_toomany, _("Cannot add \2%s\2 to \2%s\2 metadata table, it is full."),
                    property, entity(mu)->name);
        return;
    }

    if (strlen(property) > 32 || strlen(value) > 300 || has_ctrl_chars(property))
    {
        command_fail(si, fault_badparams, _("Parameters are too long. Aborting."));
        return;
    }

    md = metadata_add(mu, property, value);
    if (md != NULL)
    {
        mdchange.target = mu;
        mdchange.name = md->name;
        mdchange.value = md->value;
        hook_call_metadata_change(&mdchange);
    }
    logcommand(si, CMDLOG_SET, "FPROPERTY: \2%s\2 to \2%s\2", property, value);
    command_success_nodata(si, _("Metadata entry \2%s\2 added."), property);
}


/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
