/* Shared header file for iptables extension for the GTPU target and GTPu KLM
 *
 * Copyright (c) 2010-2011 Polaris Networks
 * Author: Pradip Biswas <pradip_biswas@polarisnetworks.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

enum xt_gtpu_mode_
{
    PARAM_GTPU_ACTION_ADD = 1 << 8,
    PARAM_GTPU_ACTION_REM = 1 << 9,
    PARAM_GTPU_ACTION_TRANSPORT = 1 << 10,
};

struct xt_gtpu_target_info
{
    u_int32_t laddr;
    u_int32_t raddr;
    u_int32_t ltun;
    u_int32_t rtun;
    u_int32_t action;
};

