#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
PLUGIN_NAME=		modsecurity
PLUGIN_VERSION=		1.0.1
PLUGIN_COMMENT=		OWASP Core Rule Set in front of published sites, through ModSecurity
PLUGIN_MAINTAINER=	eg2@live.com
PLUGIN_DEPENDS=		apache24 ap24-mod_security

.include "../../Mk/plugins.mk"
