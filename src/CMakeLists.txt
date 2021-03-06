############################################################################
# CMakeLists.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
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

set(INCLUDES ${ANTLR3C_INCLUDE_DIRS})
set(LIBS ${ANTLR3C_LIBRARIES})

if(Threads_FOUND)
	if(CMAKE_USE_PTHREADS_INIT AND NOT CMAKE_SYSTEM_NAME MATCHES "QNX")
		list(APPEND LIBS pthread)
	endif()
endif()
if(HAVE_LIBDL)
	list(APPEND LIBS dl)
endif()
if(HAVE_LIBRT)
	list(APPEND LIBS rt)
endif()
if(HAVE_RESINIT)
	list(APPEND LIBS resolv)
endif()
if(WIN32)
	list(APPEND LIBS ws2_32)
endif()

set(SDP_GENERATED_SOURCE_FILES_C
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sdpLexer.c
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sdpLexer.h
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sdpParser.c
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sdpParser.h
)
add_custom_command(
	OUTPUT ${SDP_GENERATED_SOURCE_FILES_C}
	COMMAND ${ANTLR3_COMMAND} -make -Xmultithreaded -Xconversiontimeout 10000 -fo ${CMAKE_CURRENT_BINARY_DIR}/grammars ${CMAKE_CURRENT_SOURCE_DIR}/grammars/belle_sdp.g
	DEPENDS grammars/belle_sdp.g
)

set(SIP_MESSAGE_GENERATED_SOURCE_FILES_C
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sip_messageLexer.c
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sip_messageLexer.h
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sip_messageParser.c
	${CMAKE_CURRENT_BINARY_DIR}/grammars/belle_sip_messageParser.h
)
add_custom_command(
	OUTPUT ${SIP_MESSAGE_GENERATED_SOURCE_FILES_C}
	COMMAND ${ANTLR3_COMMAND} -make -Xmultithreaded -Xconversiontimeout 10000 -fo ${CMAKE_CURRENT_BINARY_DIR}/grammars ${CMAKE_CURRENT_SOURCE_DIR}/grammars/belle_sip_message.g
	DEPENDS grammars/belle_sip_message.g
)

set_source_files_properties(${SDP_GENERATED_SOURCE_FILES_C} ${SIP_MESSAGE_GENERATED_SOURCE_FILES_C} PROPERTIES GENERATED TRUE)

if(ENABLE_TLS)
	set(TLS_SOURCE_FILES_C
		transports/tls_listeningpoint_polarssl.c
		transports/tls_channel_polarssl.c
	)
	list(APPEND INCLUDES ${POLARSSL_INCLUDE_DIR})
	list(APPEND LIBS ${POLARSSL_LIBRARIES})
endif()

if(ENABLE_TUNNEL)
	set(TUNNEL_SOURCE_FILES_C
		transports/tunnel_listeningpoint.c
		transports/tunnel_channel.c
	)
	set(TUNNEL_SOURCE_FILES_CXX
		transports/tunnel_wrapper.cc
	)
	list(APPEND LIBS ${TUNNEL_LIBRARIES})
endif()

set(BELLE_SIP_SOURCE_FILES_C
	auth_event.c
	auth_helper.c
	belle_sdp_impl.c
	belle_sip_dict.c
	belle_sip_headers_impl.c
	belle_sip_internal.h
	belle_sip_loop.c
	belle_sip_object.c
	belle_sip_parameters.c
	belle_sip_resolver.c
	belle_sip_uri_impl.c
	belle_sip_utils.c
	bodyhandler.c
	channel.c
	channel.h
	clock_gettime.c
	clock_gettime.h
	dialog.c
	dns.c
	dns.h
	generic-uri.c
	http-listener.c
	http-message.c
	http-provider.c
	ict.c
	ist.c
	listeningpoint.c
	listeningpoint_internal.h
	md5.c
	md5.h
	message.c
	nict.c
	nist.c
	parserutils.h
	port.c
	port.h
	provider.c
	refresher.c
	siplistener.c
	sipstack.c
	transaction.c
	transports/stream_channel.c
	transports/stream_channel.h
	transports/stream_listeningpoint.c
	transports/udp_channel.c
	transports/udp_listeningpoint.c
	grammars/belle_sip_message.g
	grammars/belle_sdp.g
	${SDP_GENERATED_SOURCE_FILES_C}
	${SIP_MESSAGE_GENERATED_SOURCE_FILES_C}
	${TLS_SOURCE_FILES_C}
	${TUNNEL_SOURCE_FILES_C}
)
set(BELLE_SIP_SOURCE_FILES_CXX
	${TUNNEL_SOURCE_FILES_CXX}
)
if(APPLE)
	set(BELLE_SIP_SOURCE_FILES_OBJC
		backgroundtask.m
	)
endif()

apply_compile_flags(BELLE_SIP_SOURCE_FILES_C "CPP" "C")
apply_compile_flags(BELLE_SIP_SOURCE_FILES_OBJC "CPP" "OBJC")
if(BELLE_SIP_SOURCE_FILES_CXX)
	set_source_files_properties(${BELLE_SIP_SOURCE_FILES_CXX} PROPERTIES LANGUAGE CXX)
	apply_compile_flags(BELLE_SIP_SOURCE_FILES_CXX "CPP" "CXX")
endif()

if(ENABLE_STATIC)
	add_library(bellesip STATIC ${BELLE_SIP_HEADER_FILES} ${BELLE_SIP_SOURCE_FILES_C} ${BELLE_SIP_SOURCE_FILES_CXX} ${BELLE_SIP_SOURCE_FILES_OBJC})
else()
	add_library(bellesip SHARED ${BELLE_SIP_HEADER_FILES} ${BELLE_SIP_SOURCE_FILES_C} ${BELLE_SIP_SOURCE_FILES_CXX} ${BELLE_SIP_SOURCE_FILES_OBJC})
	set_target_properties(bellesip PROPERTIES VERSION 0.0.0 SOVERSION 0)
	if(MSVC)
		if(CMAKE_BUILD_TYPE STREQUAL "Debug")
			install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Debug/bellesip.pdb
				DESTINATION bin
				PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
			)
		endif()
	endif()
endif()
set_target_properties(bellesip PROPERTIES LINKER_LANGUAGE CXX)
string(REPLACE ";" " " LINK_FLAGS_STR "${LINK_FLAGS}")
if(NOT "${LINK_FLAGS_STR}" STREQUAL "")
       set_target_properties(bellesip PROPERTIES LINK_FLAGS "${LINK_FLAGS_STR}")
endif()
target_include_directories(bellesip PUBLIC ${INCLUDES})
target_link_libraries(bellesip ${LIBS})

install(TARGETS bellesip EXPORT ${EXPORT_TARGETS_NAME}Targets
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
