/*
	belle-sip - SIP (RFC3261) library.
    Copyright (C) 2010  Belledonne Communications SARL

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef BELLE_SIP_MESSAGE_H
#define BELLE_SIP_MESSAGE_H

typedef struct _belle_sip_message belle_sip_message_t;
typedef struct _belle_sip_request belle_sip_request_t;
typedef struct _belle_sip_response belle_sip_response_t;

#define BELLE_SIP_MESSAGE(obj)			BELLE_SIP_CAST(obj,belle_sip_message_t)
#define BELLE_SIP_REQUEST(obj)			BELLE_SIP_CAST(obj,belle_sip_request_t)
#define BELLE_SIP_RESPONSE(obj)		BELLE_SIP_CAST(obj,belle_sip_response_t)

BELLE_SIP_BEGIN_DECLS

belle_sip_message_t* belle_sip_message_parse(const char* raw);
/**
 * Parse sip message from a raw buffer
 * @param [in] buff buffer to be parsed
 * @param [in] buff_length size of the buffer to be parsed
 * @param [out] message_length number of bytes read
 * @return parsed message
 */
belle_sip_message_t* belle_sip_message_parse_raw (const char* buff, size_t buff_length,size_t* message_length );

int belle_sip_message_is_request(belle_sip_message_t *msg);
belle_sip_request_t* belle_sip_request_new();
belle_sip_request_t* belle_sip_request_parse(const char* raw);






belle_sip_uri_t* belle_sip_request_get_uri(belle_sip_request_t* request);
void belle_sip_request_set_uri(belle_sip_request_t* request,belle_sip_uri_t* uri);
const char* belle_sip_request_get_method(const belle_sip_request_t* request);
void belle_sip_request_set_method(belle_sip_request_t* request,const char* method);

int belle_sip_message_is_response(belle_sip_message_t *msg);

belle_sip_header_t *belle_sip_message_get_header(belle_sip_message_t *msg, const char *header_name);

const belle_sip_list_t* belle_sip_message_get_headers(belle_sip_message_t *message,const char* header_name);

/**
 * add an header to this message
 * @param msg
 * @param header to add, must be one of header type
 */
void belle_sip_message_add_header(belle_sip_message_t *msg, belle_sip_header_t* header);

void belle_sip_message_add_headers(belle_sip_message_t *message, const belle_sip_list_t *header_list);

char *belle_sip_message_to_string(belle_sip_message_t *msg);
const char* belle_sip_message_get_body(belle_sip_message_t *msg);
void belle_sip_message_set_body(belle_sip_message_t *msg,char* body,unsigned int size);

int belle_sip_response_get_status_code(const belle_sip_response_t *response);
void belle_sip_response_set_status_code(belle_sip_response_t *response,int status);

const char* belle_sip_response_get_reason_phrase(const belle_sip_response_t *response);
void belle_sip_response_set_reason_phrase(belle_sip_response_t *response,const char* reason_phrase);


belle_sip_response_t *belle_sip_response_new(void);

belle_sip_response_t *belle_sip_response_new_from_request(belle_sip_request_t *req, int status_code);

BELLE_SIP_END_DECLS

#endif
