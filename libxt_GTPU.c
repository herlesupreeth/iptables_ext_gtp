/* Shared library add-on to iptables for the GTPU target
 *
 * Copyright (c) 2010-2011 Polaris Networks
 * Author: Pradip Biswas <pradip_biswas@polarisnetworks.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#include "xt_GTPU.h"

#if (IPTVERSION <= 135)
#include <iptables.h>
#elif (IPTVERSION > 135)
#include <xtables.h>
#endif

#if (IPTVERSION <= 135)
#define GTPU_PARAM_BAD_VALUE 0
#define GTPU_PARAM_ONLY_ONCE 1
#define XT_GTPU_VERSION IPTABLES_VERSION_STRING
#define gtpu_strtoui(s,v,m,M) !string_to_number(s,m,M,v)
#define gtpu_exit_error exit_error
#elif (IPTVERSION > 135) && (IPTVERSION <= 141) 
#define GTPU_PARAM_BAD_VALUE P_BAD_VALUE
#define GTPU_PARAM_ONLY_ONCE P_ONLY_ONCE
#define XT_GTPU_VERSION XTABLES_VERSION
#define gtpu_param_act param_act
#define gtpu_strtoui(s,v,m,M) !string_to_number(s,m,M,v)
#define gtpu_exit_error exit_error
#elif (IPTVERSION > 141)
#define GTPU_PARAM_BAD_VALUE XTF_BAD_VALUE
#define GTPU_PARAM_ONLY_ONCE XTF_ONLY_ONCE
#define XT_GTPU_VERSION XTABLES_VERSION
#define gtpu_param_act xtables_param_act
#define gtpu_strtoui(s,v,m,M) xtables_strtoui(s,NULL,v,m,M)
#define gtpu_exit_error xtables_error
#endif

enum {
    PARAM_LADDR = 1 << 0,
    PARAM_LTUN = 1 << 1,
    PARAM_RADDR = 1 << 2,
    PARAM_RTUN = 1 << 3,
    PARAM_ACTION = 1 << 4,
};

static void GTPU_help(void)
{
    printf(
"GTPU target options\n"
"  --action         value        Set action <value: add|remove|transport>\n"
"  --own-ip         value        Set own IP address\n"
"  --own-tun        value        Set own tunnel id <value: 1-2^31>\n"
"  --peer-ip        value        Set peer IP address\n"
"  --peer-tun       value        Set peer tunnel id <value: 1-2^31>\n");
}

#if (IPTVERSION <= 135)
/* Stolen from iptables v1.4.7 code */
void gtpu_param_act(unsigned int status, const char *p1, ...)
{
        const char *p2, *p3;
        va_list args;
        int b;

        va_start(args, p1);

        switch (status) {
        case GTPU_PARAM_ONLY_ONCE:
                p2 = va_arg(args, const char *);
                b  = va_arg(args, unsigned int);
                if (!b)
                        return;
                exit_error(PARAMETER_PROBLEM,
                           "%s: \"%s\" option may only be specified once",
                           p1, p2);
                break;
        case GTPU_PARAM_BAD_VALUE:
                p2 = va_arg(args, const char *);
                p3 = va_arg(args, const char *);
                exit_error(PARAMETER_PROBLEM,
                           "%s: Bad value for \"%s\" option: \"%s\"",
                           p1, p2, p3);
                break;
        default:
                exit_error(status, "%s", "Unknown error");
                break;
        }

        va_end(args);
}

#endif

static void parse_gtpu_addr(const char *s, struct xt_gtpu_target_info *info, int flag)
{
    in_addr_t addr;

    if ((addr = inet_addr(s)) == -1)
    {
        switch (flag)
        {
            case PARAM_LADDR:
                gtpu_param_act(GTPU_PARAM_BAD_VALUE, "GTPU", "--own-ip", s);
                break;
            case PARAM_RADDR:
                gtpu_param_act(GTPU_PARAM_BAD_VALUE, "GTPU", "--peer-ip", s);
                break;
        }
    }
     
    switch (flag)
    {
        case PARAM_LADDR:
            info->laddr = addr;
            break;
        case PARAM_RADDR:
            info->raddr = addr;
            break;
    }
}

static void parse_gtpu_tunid(char *s, struct xt_gtpu_target_info *info, int flag)
{
    unsigned int value;

    if (!gtpu_strtoui(s, &value, 0, UINT32_MAX))
    {
        switch (flag)
        {
            case PARAM_LTUN:
                gtpu_param_act(GTPU_PARAM_BAD_VALUE, "GTPU", "--own-tun", s);
                break;
            case PARAM_RTUN:
                gtpu_param_act(GTPU_PARAM_BAD_VALUE, "GTPU", "--peer-tun", s);
                break;
        }
    }

    switch (flag)
    {
        case PARAM_LTUN:
            info->ltun = value;
            break;
        case PARAM_RTUN:
            info->rtun = value;
            break;
    }
}

static void parse_gtpu_action(char *s, struct xt_gtpu_target_info *info, unsigned int *flags)
{
    if (!strcmp(s, "add"))
    {
        info->action = PARAM_GTPU_ACTION_ADD;
        *flags |= PARAM_GTPU_ACTION_ADD;
    }
    else if (!strcmp(s, "remove"))
    {
        info->action = PARAM_GTPU_ACTION_REM;
        *flags |= PARAM_GTPU_ACTION_REM;
    }
    else if (!strcmp(s, "transport"))
    {
        info->action = PARAM_GTPU_ACTION_TRANSPORT;
        *flags |= PARAM_GTPU_ACTION_TRANSPORT;
    }
    else
    {
        gtpu_param_act(GTPU_PARAM_BAD_VALUE, "GTPU", "--action", s);
    }
}

#if (IPTVERSION <= 135)
static int
GTPU_parse(int c, char **argv, int invert, unsigned int *flags,
           const struct ipt_entry *entry,
           struct ipt_entry_target **target)
#else
static int
GTPU_parse(int c, char **argv, int invert, unsigned int *flags,
           const void *entry, struct xt_entry_target **target)
#endif
{
    struct xt_gtpu_target_info *info = (struct xt_gtpu_target_info *) (*target)->data;

    switch (c) 
    {
        case '1':
                gtpu_param_act(GTPU_PARAM_ONLY_ONCE, "GTPU", "--own-ip", *flags & PARAM_LADDR);
                parse_gtpu_addr(optarg, info, PARAM_LADDR);
                *flags |= PARAM_LADDR;
                return 1;
        case '2':
                gtpu_param_act(GTPU_PARAM_ONLY_ONCE, "GTPU", "--own-tun", *flags & PARAM_LTUN);
                parse_gtpu_tunid(optarg, info, PARAM_LTUN);
                *flags |= PARAM_LTUN;
                return 1;
        case '3':
                gtpu_param_act(GTPU_PARAM_ONLY_ONCE, "GTPU", "--peer-ip", *flags & PARAM_RADDR);
                parse_gtpu_addr(optarg, info, PARAM_RADDR);
                *flags |= PARAM_RADDR;
                return 1;
        case '4':
                gtpu_param_act(GTPU_PARAM_ONLY_ONCE, "GTPU", "--peer-tun", *flags & PARAM_RTUN);
                parse_gtpu_tunid(optarg, info, PARAM_RTUN);
                *flags |= PARAM_RTUN;
                return 1;
        case '5':
                gtpu_param_act(GTPU_PARAM_ONLY_ONCE, "GTPU", "--action", *flags & PARAM_ACTION);
                parse_gtpu_action(optarg, info, flags);
                *flags |= PARAM_ACTION;
                return 1;
    }

    return 1;
}

static void GTPU_check(unsigned int flags)
{
    if (!(flags & PARAM_ACTION))
    {
        gtpu_exit_error(PARAMETER_PROBLEM, "GTPU: You must specify action");
    }

    if (flags & PARAM_GTPU_ACTION_REM)
    {
        return;
    }
    
    if (!(flags & PARAM_LADDR))
    {
        gtpu_exit_error(PARAMETER_PROBLEM, "GTPU: You must specify local addr");
    }
    if (!(flags & PARAM_LTUN))
    {
        gtpu_exit_error(PARAMETER_PROBLEM, "GTPU: You must specify local tunnel id");
    }
    if (!(flags & PARAM_RADDR))
    {
        gtpu_exit_error(PARAMETER_PROBLEM, "GTPU: You must specify remote addr");
    }
    if (!(flags & PARAM_RTUN))
    {
        gtpu_exit_error(PARAMETER_PROBLEM, "GTPU: You must specify remote tunnel id");
    }
}

static void convert_action_to_string(int action, char *actionstr)
{
    switch(action)
    {
        case PARAM_GTPU_ACTION_ADD:
            sprintf (actionstr, "add");
            break;
        case PARAM_GTPU_ACTION_REM:
            sprintf (actionstr, "remove");
            break;
        case PARAM_GTPU_ACTION_TRANSPORT:
            sprintf (actionstr, "transport");
            break;
        default :
            sprintf (actionstr, "unspecified!!!");
            break;
    }
}

#if (IPTVERSION <= 135)
static void
GTPU_print(const struct ipt_ip *ip,
         const struct ipt_entry_target *target,
         int numeric)

#else
static void
GTPU_print(const void *ip, 
           const struct xt_entry_target *target,
           int numeric)
#endif
{
    const struct xt_gtpu_target_info *info =
        (struct xt_gtpu_target_info *) target->data;

    char laddr[64], raddr[64], actionstr[32];

    convert_action_to_string(info->action, actionstr);

    if (info->action == PARAM_GTPU_ACTION_REM)
    {
        printf("GTPU action: %s", actionstr);
        return;
    }

    sprintf (laddr, "%s", inet_ntoa(*(struct in_addr*)&info->laddr));
    sprintf (raddr, "%s", inet_ntoa(*(struct in_addr*)&info->raddr));
    printf("GTPU self: %s tunnel: 0x%x / peer: %s tunnel: 0x%x / action: %s", 
           laddr, info->ltun, raddr, info->rtun, actionstr);
}

static struct option GTPU_opts[] = {
    { "own-ip", 1, NULL, '1' },
    { "own-tun", 1, NULL, '2' },
    { "peer-ip", 1, NULL, '3' },
    { "peer-tun", 1, NULL, '4' },
    { "action", 1, NULL, '5' },
    { .name = NULL }
};

#if (IPTVERSION <= 135)
static struct iptables_target gtpu_tg_reg = {
#else
static struct xtables_target gtpu_tg_reg = {
#endif
    .name             = "GTPU",
    .version          = XT_GTPU_VERSION,
#if (IPTVERSION > 135)
    .family           = NFPROTO_IPV4,
#endif
    .size             = XT_ALIGN(sizeof(struct xt_gtpu_target_info)),
    .userspacesize    = XT_ALIGN(sizeof(struct xt_gtpu_target_info)),
    .help             = GTPU_help,
    .parse            = GTPU_parse,
    .final_check      = GTPU_check,
    .print            = GTPU_print,
    .extra_opts       = GTPU_opts,
};

void _init(void)
{
#if (IPTVERSION <= 135)
    register_target(&gtpu_tg_reg);
#else
    xtables_register_target(&gtpu_tg_reg);
#endif
}

