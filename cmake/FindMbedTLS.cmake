############################################################################
# FindMbedTLS.cmake
# Copyright (C) 2015  Belledonne Communications, James Cowgill
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
############################################################################
#
# - Find the mbedtls include directory and libraries
# - If any components are specified, MBEDTLS_LIRARIES will only include
#   the libraries asked for (out of crypto, x509 and tls).
#
#  MBEDTLS_FOUND - system has mbedtls
#  MBEDTLS_INCLUDE_DIRS - the mbedtlsl include directory
#  MBEDTLS_LIBRARIES - The libraries needed to use mbedtls

include(FindPackageHandleStandardArgs)

find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)

find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDTLS_LIBRARY mbedtls)

set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})

if (NOT MbedTLS_FIND_COMPONENTS)
	list(APPEND MbedTLS_FIND_COMPONENTS crypto x509 tls)
endif()

set(MBEDTLS_LIBRARIES "")
foreach(component ${MbedTLS_FIND_COMPONENTS})
	string(TOUPPER ${component} component)
	list(APPEND MBEDTLS_LIBRARIES ${MBED${component}_LIBRARY})
endforeach()

find_package_handle_standard_args(mbedTLS DEFAULT_MSG MBEDTLS_INCLUDE_DIR
	MBEDCRYPTO_LIBRARY MBEDX509_LIBRARY MBEDTLS_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY MBEDX509_LIBRARY
	MBEDTLS_LIBRARY)
