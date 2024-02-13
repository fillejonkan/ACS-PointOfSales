#ifndef INCLUSION_GUARD_SQUARE_COMMANDS_H
#define INCLUSION_GUARD_SQUARE_COMMANDS_H

/** @file square_commands.h
 * @Brief Macros for Square API commands
 *
 * Just a header file to hide the ugly cURL macro.
 */

#define SQUARE_GET_MERCHANT "curl https://connect.squareup.com/v2/merchants/%s \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Authorization: Bearer %s\" \
  -H \"Content-Type: application/json\" \
  -w 'HTTP:%%{http_code}' --max-time 5"

#define SQUARE_LIST_LOCATIONS "curl -H \"Square-Version: 2020-12-16\" \
  -H \"Authorization: Bearer %s\" \
  -H \"Content-Type: application/json\" \
  -w 'HTTP:%%{http_code}' --max-time 5\
  https://connect.squareup.com/v2/locations"

#define SQUARE_GET_ORDERS "curl https://connect.squareup.com/v2/orders/search \
  -X POST \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Authorization: Bearer %s\" \
  -H \"Content-Type: application/json\" \
  -d '{\
    \"location_ids\": [\
      \"%s\"\
    ],\
    \"query\": {\
      \"filter\": {\
        \"date_time_filter\": {\
          \"closed_at\": {\
            \"start_at\": \"%s\"\
          }\
        },\
        \"state_filter\": {\
          \"states\": [\
            \"COMPLETED\",\
            \"CANCELED\"\
          ]\
        }\
      },\
      \"sort\": {\
        \"sort_field\": \"CLOSED_AT\",\
        \"sort_order\": \"ASC\"\
      }\
    },\
    \"return_entries\": false\
  }'"

#define SQUARE_GET_TOKEN "curl \
  -X POST \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Content-Type: application/json\" \
  --data \'{ \
  	\"client_id\": \"TBD\",\
    \"client_secret\": \"TBD\",\
    \"code\": \"%s\", \
    \"grant_type\": \"authorization_code\"\
	}\' https://connect.squareup.com/oauth2/token"

#define SQUARE_REFRESH_TOKEN "curl \
  -X POST \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Content-Type: application/json\" \
  -w 'HTTP:%%{http_code}' --max-time 5\
  --data \'{ \
    \"client_id\": \"TBD\",\
    \"client_secret\": \"TBD\",\
    \"refresh_token\": \"%s\", \
    \"grant_type\": \"refresh_token\"\
  }\' https://connect.squareup.com/oauth2/token"

#define SQUARE_REVOKE_TOKEN "curl https://connect.squareup.com/oauth2/revoke \
  -X POST \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Authorization: Client TBD\" \
  -H \"Content-Type: application/json\" \
  --data \'{ \
    \"access_token\": \"%s\", \
    \"client_id\": \"sq0idp-bWA2pNYKzlUaMyJ6_XIcKg\",\
    \"revoke_only_access_token\": true \
  }\'"

#define SQUARE_GET_CUSTOMER "curl https://connect.squareup.com/v2/customers/%s \
  -H \"Square-Version: 2020-12-16\" \
  -H \"Authorization: Bearer %s\" \
  -H \"Content-Type: application/json\" \
  -w 'HTTP:%%{http_code}' --max-time 5"

 #endif /* INCLUSION_GUARD_SQUARE_COMMANDS_H */