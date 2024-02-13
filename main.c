#define _XOPEN_SOURCE 700

#include <glib.h>
#include <glib-object.h>
#include <glib/gprintf.h>

#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <axsdk/axevent.h>
#include <axoverlay.h>

#include "metadata_pair.h"
#include "overlay.h"
#include "camera/camera.h"
#include "acs.h"
#include "debug.h"
#include "square_commands.h"
#include "cJSON.h"


/** @mainpage Metadata ACS Overview
 *
 * @section intro_sec Introduction
 *
 * The purpose of the application is to subscribe to one user configurable
 * analytic with Metadata.
 *
 * @section Architecture
 *
 * This is a fairly simple application that has a web page which will list
 * all available ACAP VAPIX event containing usable data to push to ACS.
 *
 * User can select which event / category to subscribe to and what data items
 * to push to ACS using a series of dropdown menus.
 *
 * The user can furthermore configure all of the necessary parameters for the
 * ACS communication. Server Address, Source Key ID etc, and there are some
 * functions to help test the reporting chain as well.
 *
 * There is one main HTML file containing the HTML and JavaScript handling logic
 * with populating the dropdowns etc and a few C files handling the ACAP
 * framework stuff and ACS interface.
 *
 * 
 * @subsection file_sec Files
 *
 * main.c is the main ACAP entry point and handles event callbacks, parameters
 * etc. 
 *
 * It will use metadata_push.c to interface with ACS and push the event
 * data in to the external data search engine with the correct JSON format.
 * 
 * debug.c is a small file that handles enabling / disabling of dynamic logging.
 *
 * @subsection Application Parameters
 *
 * - ServerAddress IP address of the ACS Server.
 *
 * - SourceID      Configured Source Key ID in ACS.
 *
 * - Username      Username for ACS Server.
 *
 * - Password      Password for ACS Server.
 *
 * - Enabled       Toggle reporting on / off. Event subscription still active.
 *
 * - Analytic      Selection of Analytic category. E.g. FenceGuard.
 *
 * - Category      Seclection of Subcategory. E.g. Camera1Profile1.
 *                "Uncategorized" is magic and used for ACAPs with no
 *                subcategory.
 *
 * - Items         Semi-colon separated and terminated list of data items.
 *                E.g. plate;description;country;
 *
 * - DebugEnabled    = "no" type="bool:no,yes"
 *
 * @subsection CGIs
 *
 * - settings/testreporting Sends a test command to ACS with the current
 *                         configured data items. Check if command is received
 *                         OK and if not indicate reason to user.
 *
 * - settings/get           Get all of the parameters in one CGI call.
 *
 */

/** @file main.c
 * @Brief Main application framework.
 *
 * Main ACAP framework. Handle user params, CGI, event subscription etc.
 * Distribute accordingly to other entities.
 */

/******************** MACRO DEFINITION SECTION ********************************/

/**
 * APP ID used for logs etc.
 */
#define APP_ID              "ACSPointOfSales"

/**
 * Nice name used for App
 */
#define APP_NICE_NAME       "ACSPointOfSales"

/**
 * Max number of metadata items
 */
#define MAX_ITEMS (20)

/**
 * Number of days left on Access Token until we want to refresh it
 */
#define SQUARE_REFRESH_TOKEN_DAYS (12)

#define SQUARE_REFRESH_TIME (5000)

/******************** LOCAL VARIABLE DECLARATION SECTION **********************/

/**
 * Main context for GLib.
 */
static GMainLoop *loop;

/**
 * Handle for ACAP event subsystem
 */
static AXEventHandler *event_handler;

/**
 * Subscription ID for zone crossing alarm.
 */
static int event_subscription_id = -1;

/**
* Extra debug logging enabled or not
*/
static char *par_debug_enabled = NULL;

/**
* Access Token for Square API
*/
static char *par_access_token  = NULL;
static char *par_refresh_token = NULL;
static char *par_expiration    = NULL;
static char *par_merchant_id   = NULL;

/**
* Handle for metdata push instance
*/
static acs_handle acs            = NULL;

/**
* Handle for overlay instance
*/
static overlay_handle ovl_handle = NULL;

static char *start_zulu_time = NULL;

static char* par_location_id = NULL;

/******************** LOCAL FUNCTION DECLARATION SECTION **********************/

/**
 * Quit the application when terminate signals is being sent.
 *
 * @param signo Unix signal number.
 *
 * @return No return value.
 */
static void handle_sigterm(int signo);

/**
 * Register callback to SIGTERM and SIGINT signals.
 *
 * @return No return value.
 */
static void init_signals();

/**
 * Callback function for changes to Server Address parameter.
 *
 * @param value The new value for Server Addres.
 *
 * @return No return value. 
 */
static void set_server_address(const char *value);

/**
 * Callback function for changes to source ID parameter
 * 
 * @param value The new value for Source ID
 *
 * @return No return value.
 */
static void set_source_id(const char *value);

/**
 * Callback function for changes to Username parameter
 * update ACS API credentials if needed.
 *
 * @param value The new value for Username.
 *
 * @return No return value.
 */
static void set_username(const char *value);

/**
 * Callback function for changes to Password parameter
 * update ACS API credentials if needed.
 *
 * @param value The new value for Password.
 *
 * @return No return value.
 */
static void set_password(const char *value);

/**
 * Callback function for Enabled parameter.
 *
 * @param value The new value for Enabled.
 *
 * @return No return value.
 */
static void set_enabled(const char *value);

/**
 * Callback function for Access Token Parameter.
 *
 * @param value The new value for Access Token.
 *
 * @return No return value.
 */
static void set_access_token(const char *value);

/**
 * Callback function for Access Token Parameter.
 *
 * @param value The new value for Access Token.
 *
 * @return No return value.
 */
static void set_refresh_token(const char *value);

/**
 * Callback function for Access Token Parameter.
 *
 * @param value The new value for Access Token.
 *
 * @return No return value.
 */
static void set_expiration(const char *value);
static void set_merchant_id(const char *value);

/**
 * Callback function for the Square Location Parameter.
 *
 * @param value The new value for Square Location.
 *
 * @return No return value.
 */
static void set_location(const char *value);

/**
 * Callback function debug enabled parameter. This is used to dynamically
 * enable / disable extra debug printing.
 *
 * @param value The new value for DebugEnabled.
 *
 * @return No return value.
 */
static void set_debug_enabled(const char *value);

/**
 * CGI callback function for testing the reporting chain.
 *
 * @param http    HTTP_Reply object to use for sending response.
 * @param options Unused HTTP options parameter required by API.
 *
 * @return No return value.
 */
static void cgi_test_reporting(CAMERA_HTTP_Reply http,
                               CAMERA_HTTP_Options options);

/**
 * CGI function for getting all parameters at once.
 *
 * @param http    HTTP_Reply object to use for sending response.
 * @param options Unused HTTP options parameter required by API.
 *
 * @return No return value.
 */
static void cgi_settings_get(CAMERA_HTTP_Reply http,
                             CAMERA_HTTP_Options options);

static void cgi_set_code(CAMERA_HTTP_Reply http,
    CAMERA_HTTP_Options options);

static void cgi_get_locations(CAMERA_HTTP_Reply http,
    CAMERA_HTTP_Options options);

void get_square_orders(const char *loc_id);
static GList * list_append_pair(GList *list, const char *name, const char *value);
static const char* get_string_safe(const cJSON *cjs);
static char * check_HTTP_response(const char *buffer);
static void revoke_square_code();
static char * square_get_customer_name(const char *customer_id);
void acs_done_callback(void);


static char *get_zulu_time()
{
    /** 
     * Retrieve current UTC time as needed by the API
     */
    char outstr[200];
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    tmp = gmtime(&t);

    if (tmp == NULL) {
        ERR("Failed to get time value");
        return NULL;
    }

    if (strftime(outstr, sizeof(outstr), "%FT%TZ", tmp) == 0) {
        ERR("Failed to convert time");
        return NULL;
    }

    return g_strdup(outstr);
}

static int get_remaining_days(const char *rfc_time)
{
    g_assert(rfc_time);

    time_t curr_t = time(NULL);

    struct tm tm;
    if (strptime(rfc_time, "%FT%T", &tm) == NULL) {
        ERR("Failed to parse time");
        return -1;
    }

    time_t ref_t = mktime(&tm);

    if (ref_t == -1) {
        ERR("Failed to convert time");
        return -1;
    }

    int remaining_days = (ref_t - curr_t) / (60*60*24);

    return remaining_days;
}

static gboolean square_initialized()
{
    if (strlen(par_access_token) == 0 || strlen(par_refresh_token) == 0 ||
        strlen(par_expiration)   == 0 || strlen(par_location_id)   == 0) {
        return FALSE;
    }

    return TRUE;
}

static char * square_get_customer_name(const char *customer_id)
{
    gchar *stdout = NULL;
    gchar *stderr = NULL;
    cJSON *cjs    = NULL;
    char *ret     = NULL;

    gchar *command = g_strdup_printf(SQUARE_GET_CUSTOMER, customer_id,
        par_access_token);

    (void) g_spawn_command_line_sync(command, &stdout, &stderr, NULL, NULL);
    g_free(command);

    LOG("Got Stdout: \n%s", stdout);

    cjs = cJSON_Parse(stdout);

    if (!cjs) {
        goto exit;
    }

    const cJSON *customer  = cJSON_GetObjectItem(cjs, "customer");

    if (!customer) {
        ret = g_strdup("NA");
        goto exit;
    }

    const cJSON *family_name = cJSON_GetObjectItem(customer, "family_name");
    const cJSON *given_name  = cJSON_GetObjectItem(customer, "given_name");

    ret = g_strdup_printf("%s %s", get_string_safe(given_name),
        get_string_safe(family_name));

exit:
    g_free(stdout);
    g_free(stderr);
    cJSON_Delete(cjs);

    return ret;    
}

static void square_refresh_token()
{
    gchar *stdout = NULL;
    gchar *stderr = NULL;
    cJSON *cjs    = NULL;
    gchar *error  = NULL;

    gchar *command = g_strdup_printf(SQUARE_REFRESH_TOKEN, par_refresh_token);

    (void) g_spawn_command_line_sync(command, &stdout, &stderr, NULL, NULL);
    g_free(command);

    LOG("Got Stdout: \n%s", stdout);

    error = check_HTTP_response(stdout);
    if (error && strcmp("Unauthorized", error) == 0) {
        ERR("Bad token, reset!");
        revoke_square_code();
        goto exit;
    }

    cjs = cJSON_Parse(stdout);

    if (!cjs) {
        goto exit;
    }

    const cJSON *access_token  = cJSON_GetObjectItem(cjs, "access_token");
    const cJSON *refresh_token = cJSON_GetObjectItem(cjs, "refresh_token");
    const cJSON *expiration    = cJSON_GetObjectItem(cjs, "expires_at");
    const cJSON *merchant_id   = cJSON_GetObjectItem(cjs, "merchant_id");

    LOG("%s", cJSON_Print(cjs));

    if (access_token && refresh_token && expiration && merchant_id) {
        const gchar *access_string        = get_string_safe(access_token);
        const gchar *refresh_string       = get_string_safe(refresh_token);
        const gchar *expiration_string    = get_string_safe(expiration);
        const gchar *merchant_id_string   = get_string_safe(merchant_id);

        camera_param_set("SquareAccessToken",  access_string);
        camera_param_set("SquareRefreshToken", refresh_string);
        camera_param_set("SquareExpiration",   expiration_string);
        camera_param_set("SquareMerchant",     merchant_id_string);

        LOG("Got new credentials: AT=%s, RT=%s, EXP=%s, M=%s", access_string,
            refresh_string, expiration_string, merchant_id_string);

    } else {
        LOG("Failed to get access token from response");
    }

exit:
    g_free(error);
    g_free(stdout);
    g_free(stderr);
    cJSON_Delete(cjs);    
}

static gboolean on_timeout(gpointer data)
{
    (void) data;

    char *zt = get_zulu_time();
    LOG("Current time %s", zt);
    g_free(zt);

    if (!square_initialized()) {
        LOG("Square not initialized, skip timeout");
        return TRUE;
    }

    int days_left = get_remaining_days(par_expiration);

    LOG("Got %d remaining days", days_left);

    /* If token is expiring, refresh and cycle back next timeout */
    if (days_left < SQUARE_REFRESH_TOKEN_DAYS) {
        LOG("Refreshing Access Token");
        square_refresh_token();
        return TRUE;
    }

    get_square_orders(par_location_id);

    /* Event will trigger again when data has been processed */
    return FALSE; 
}

/******************** LOCAL FUNCTION DEFINTION SECTION ************************/

/**
 * Quit the application when terminate signals is being sent.
 */
static void handle_sigterm(int signo)
{
    LOG("GOT SIGTERM OR SIGINT, EXIT APPLICATION");

    if (loop) {
        g_main_loop_quit(loop);
    }
}

/**
 * Register callback to SIGTERM and SIGINT signals.
 */
static void init_signals()
{
    struct sigaction sa;
    sa.sa_flags = 0;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

/**
 * Callback function for changes to ServerAddress parameter
 * update ACS API settings.
 */
static void set_server_address(const char *value)
{       
    DBG_LOG("Got new Server Address %s", value);
    acs_set_ipname(acs, value);
}

/**
 * Callback function for changes to Source ID parameter
 * update ACS API settings.
 */
static void set_source_id(const char *value)
{
    DBG_LOG("Got new Source ID %s", value);
    acs_set_source(acs, value);
}

/**
 * Callback function for changes to Username parameter
 * update ACS API settings.
 */
static void set_username(const char *value)
{
    DBG_LOG("Got new Username %s", value);
    acs_set_username(acs, value);
}

/**
 * Callback function for changes to Password parameter
 * update ACS API settings.
 */
static void set_password(const char *value)
{
    DBG_LOG("Got new Password %s", value);
    acs_set_password(acs, value);
}

/**
 * Callback function for Enabled parameter.
 */
static void set_enabled(const char *value)
{
    DBG_LOG("Got new Enabled %s", value);
    acs_set_enabled(acs, value);
}

/**
 * Callback function for Items parameter. Update event subscription
 * if needed.
 */
static void set_access_token(const char *value) 
{
    DBG_LOG("Got new Access Token %s", value);
    g_free(par_access_token);
    par_access_token = g_strdup(value);
}

static void set_refresh_token(const char *value) 
{
    DBG_LOG("Got new Refresh Token %s", value);
    g_free(par_refresh_token);
    par_refresh_token = g_strdup(value);
}

static void set_expiration(const char *value) 
{
    DBG_LOG("Got new Square Expiration %s", value);
    g_free(par_expiration);
    par_expiration = g_strdup(value);
}

static void set_merchant_id(const char *value)
{
    DBG_LOG("Got new Square Merchant ID %s", value);
    g_free(par_merchant_id);
    par_merchant_id = g_strdup(value);    
}

static void set_location(const char *value) 
{
    DBG_LOG("Got new Square Location %s", value);
    g_free(par_location_id);
    par_location_id = g_strdup(value);
}

/**
 * Callback function for debug enabled parameter. Used to enable / disable
 * verbose debug printing.
 */
static void set_debug_enabled(const char *value) 
{
    if (g_strcmp0(value, par_debug_enabled) != 0) {
        g_free(par_debug_enabled);
        par_debug_enabled = g_strdup(value);

        DBG_LOG("Got new DebugEnabled %s", par_debug_enabled);

        if (g_strcmp0(par_debug_enabled, "yes") == 0) {
            set_debug(TRUE);
            DBG_LOG("Enabled debug logging");
        } else {
            DBG_LOG("Disabling debugg logging");
            set_debug(FALSE);
        }
    }
}

/**
 * Test ACS reporting. Generate dummy event according to current items config
 * but all values replaced with TEST. Perform blocking call to run MDP in order
 * to actually check output. This is done by setting Error to non-NULL.
 */
static void cgi_test_reporting(CAMERA_HTTP_Reply http,
                               CAMERA_HTTP_Options options)
{
    gchar *error  = NULL;
    gchar *result = NULL;
    GList *metadata_items = NULL;

    /* Create metadata pair and insert in list */
    mdp_item_pair *item_pair = g_try_new0(mdp_item_pair, 1);
    item_pair->name  = g_strdup("OrderID");
    item_pair->value = g_strdup("TEST");

    metadata_items   = g_list_append(metadata_items, item_pair);

    char *zt  = get_zulu_time();
    char *utc = acs_rfc_3339_interpret(zt);

    gboolean ret = acs_run(acs, metadata_items, &error, utc);

    g_free(zt);
    g_free(utc);

    if (ret == FALSE) {
        result = g_strdup("Failure");
        goto send_xml; 
    }

    result = g_strdup("Success");
    error  = g_strdup("NA");

send_xml:
    camera_http_sendXMLheader(http);
    camera_http_output(http, "<settings>");
    camera_http_output(http, "<param name='Result' value='%s'/>",
    result);
    camera_http_output(http, "<param name='Error' value='%s'/>",
    error);
    camera_http_output(http, "</settings>");

    mdp_destroy_list(&metadata_items);
    g_free(error);
    g_free(result);
}

static void revoke_square_code()
{
    if (strlen(par_access_token) == 0) {
        return;
    }

    LOG("RRRRRRRRRRRRRRREVOKING SQUARE CODE %s", par_access_token);

    gchar *command = g_strdup_printf(SQUARE_REVOKE_TOKEN, par_access_token);

    gchar *stdout = NULL;
    gchar *stderr = NULL;

    (void) g_spawn_command_line_sync(command, &stdout, &stderr, NULL, NULL);
    g_free(command);

    LOG("Got Stdout: \n%s", stdout);

    g_free(stdout);
    g_free(stderr);

    LOG("RRRRRRRRRRRRRRREVOKED TOKEN");

    camera_param_set("SquareAccessToken",  "");
    camera_param_set("SquareRefreshToken", "");
    camera_param_set("SquareExpiration",   "");
    camera_param_set("SquareMerchant",     "");
}

/**
 * Set code
 */
static void cgi_set_code(CAMERA_HTTP_Reply http,
                         CAMERA_HTTP_Options options)
{
    revoke_square_code();

    camera_http_sendXMLheader(http);

    const char *code  = camera_http_getOptionByName(options, "code");

    if(!code) {
        camera_http_output(http,
            "<error description='Syntax: param or value missing'/>");

        ERR("cgi_set_code: no code provided\n");
        return;
    }

    camera_http_output(http, "<success/>");

    LOG("Got code %s", code);

    gchar *command = g_strdup_printf(SQUARE_GET_TOKEN, code);

    gchar *stdout = NULL;
    gchar *stderr = NULL;

    (void) g_spawn_command_line_sync(command, &stdout, &stderr, NULL, NULL);
    g_free(command);

    LOG("Got Stdout: \n%s", stdout);

    cJSON *cjs = cJSON_Parse(stdout);

    g_free(stdout);
    g_free(stderr);

    if (!cjs) {
        return;
    }

    const cJSON *access_token  = cJSON_GetObjectItem(cjs, "access_token");
    const cJSON *refresh_token = cJSON_GetObjectItem(cjs, "refresh_token");
    const cJSON *expiration    = cJSON_GetObjectItem(cjs, "expires_at");
    const cJSON *merchant_id   = cJSON_GetObjectItem(cjs, "merchant_id");

    LOG("%s", cJSON_Print(cjs));

    if (access_token && refresh_token && expiration && merchant_id) {
        const gchar *access_string        = get_string_safe(access_token);
        const gchar *refresh_string       = get_string_safe(refresh_token);
        const gchar *expiration_string    = get_string_safe(expiration);
        const gchar *merchant_id_string   = get_string_safe(merchant_id);

        camera_param_set("SquareAccessToken",  access_string);
        camera_param_set("SquareRefreshToken", refresh_string);
        camera_param_set("SquareExpiration",   expiration_string);
        camera_param_set("SquareMerchant",     merchant_id_string);

        LOG("Got new credentials: AT=%s, RT=%s, EXP=%s, M=%s", access_string,
            refresh_string, expiration_string, merchant_id_string);

    } else {
        LOG("%s", "Failed to get access token from response");
    }

    cJSON_Delete(cjs);
}

/**
 * CGI function for getting all parameters at once.
 */
static void cgi_settings_get(CAMERA_HTTP_Reply http,
                             CAMERA_HTTP_Options options)
{
  gchar *server_address_encode = 
    g_uri_escape_string(acs_get_ipname(acs), NULL, FALSE);
  gchar *source_id_encode      = 
    g_uri_escape_string(acs_get_source(acs), NULL, FALSE);
  gchar *username_encode       = 
    g_uri_escape_string(acs_get_username(acs), NULL, FALSE);
  gchar *password_encode       = 
    g_uri_escape_string(acs_get_password(acs), NULL, FALSE);
  gchar *enabled_encode        = 
    g_uri_escape_string(acs_get_enabled(acs), NULL, FALSE);
 
  gchar *debug_encode          = 
    g_uri_escape_string(par_debug_enabled, NULL, FALSE);
  gchar *location_encode = 
    g_uri_escape_string(par_location_id, NULL, FALSE);

  LOG("%s", "Settings get called\n");

  camera_http_sendXMLheader(http);
  camera_http_output(http, "<settings>");
  camera_http_output(http, "<param name='ServerAddress' value='%s'/>",
    server_address_encode);
  camera_http_output(http, "<param name='SourceID' value='%s'/>",
    source_id_encode);
  camera_http_output(http, "<param name='Username' value='%s'/>",
    username_encode);
  camera_http_output(http, "<param name='Password' value='%s'/>",
    password_encode);
  camera_http_output(http, "<param name='Enabled' value='%s'/>",
    enabled_encode);
  
  camera_http_output(http, "<param name='DebugEnabled' value='%s'/>",
    debug_encode);
  camera_http_output(http, "<param name='SquareLocation' value='%s'/>",
    location_encode);
  camera_http_output(http, "</settings>");

  g_free(server_address_encode);
  g_free(source_id_encode);
  g_free(username_encode);
  g_free(password_encode);
  g_free(enabled_encode);

  g_free(debug_encode);
  g_free(location_encode);

}

/**
 * Check for JSON error messages when sending ACS command.
 */
static char * check_HTTP_response(const char *buffer)
{
    if (!buffer) {
        return g_strdup("No response");
    }

    gchar http_code[4];

    /* This is the last occurence, we always place HTTP code after body */
    gchar *code_start = g_strrstr(buffer, "HTTP");

    if (code_start) {
        int hits = sscanf(code_start, "HTTP:%3s", http_code);
        DBG_LOG("Got HTTP code %s", http_code);

        if (hits == 1) {
            if (g_strcmp0(http_code, "200") == 0) {
               return NULL;
            } else if (g_strcmp0(http_code, "000") == 0) {
                return g_strdup("Bad IP:Port");
            } else if (g_strcmp0(http_code, "401") == 0) {
                return g_strdup("Unauthorized");
            } else if (g_strcmp0(http_code, "400") == 0) {
                return g_strdup("Malformed request");
            }
        } 
    }

    return g_strdup("Unknown Error");
}

static char * get_square_merchant_name()
{
    gchar *command = g_strdup_printf(SQUARE_GET_MERCHANT, par_merchant_id,
        par_access_token);

    gchar *stdout = NULL;
    gchar *stderr = NULL;

    LOG("%s", command);

    (void) g_spawn_command_line_sync(command, &stdout, &stderr, NULL, NULL);
    g_free(command);

    LOG("stdout: \n%s", stdout);
    LOG("stderr: \n%s", stderr);

    cJSON *cjs = cJSON_Parse(stdout);

    if (!cjs) {
        ERR("Failed to get merchant info");
        return g_strdup("NA");
    }

    cJSON *merchant = cJSON_GetObjectItem(cjs, "merchant");
    cJSON *biz_name = cJSON_GetObjectItem(merchant, "business_name");

    return g_strdup(get_string_safe(biz_name));
}

/**
 * CGI function for getting all parameters at once.
 */
static void cgi_get_locations(CAMERA_HTTP_Reply http,
                              CAMERA_HTTP_Options options)
{
    cJSON *cjs     = NULL;
    gchar *stdout  = NULL;
    gchar *stderr  = NULL;
    gchar *command = g_strdup_printf(SQUARE_LIST_LOCATIONS, par_access_token);

    LOG("%s", command);

    LOG("%s", "Settings get locations called\n");

    camera_http_sendXMLheader(http);
    camera_http_output(http, "<settings>");

    (void) g_spawn_command_line_sync(command, 
        &stdout, &stderr, NULL, NULL);

    LOG("stdout: \n%s", stdout);
    LOG("stderr: \n%s", stderr);

    char *error = check_HTTP_response(stdout);

    if (error) {
        camera_http_output(http, "<result status='%s'/>", error);
        g_free(error);
        goto exit;
    }

    cjs = cJSON_Parse(stdout);

    if (!cjs) {
        ERR("Failed to get location list");
        camera_http_output(http, "<result status='%s'/>", "Parse Error");
        goto exit;
    }

    cJSON *locations = cJSON_GetObjectItem(cjs, "locations");

    if (!cJSON_IsArray(locations) || cJSON_GetArraySize(locations) < 1) {
        ERR("No valid locations found");
        camera_http_output(http, "<result status='%s'/>", "No locations");
        goto exit;
    }

    camera_http_output(http, "<result status='%s'/>", "Success");

    /* Retrieve name of merchant */
    char *merchant_name = get_square_merchant_name();
    camera_http_output(http, "<merchant name='%s'/>", merchant_name);
    g_free(merchant_name);

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, locations) {
        cJSON *id   = cJSON_GetObjectItem(elem, "id");
        cJSON *name = cJSON_GetObjectItem(elem, "name");

        if (!id || !name || !cJSON_IsString(id) || !cJSON_IsString(name)) {
            ERR("Got bad cJSON entry");
            continue;
        }

        gchar *ID_encode = 
            g_uri_escape_string(id->valuestring, NULL, FALSE);

        gchar *name_encode = 
            g_uri_escape_string(name->valuestring, NULL, FALSE);

        LOG("Got location entry ID=%s, Name=%s", ID_encode,
            name_encode); 

        camera_http_output(http, "<param ID='%s' Name='%s'/>",
            ID_encode, name_encode);

        g_free(ID_encode);
        g_free(name_encode);
        
    }
exit:
    g_free(command);
    g_free(stdout);
    g_free(stderr);
    cJSON_Delete(cjs);

    camera_http_output(http, "</settings>");
}

/******************** GLOBAL FUNCTION DEFINTION SECTION ***********************/

GList * get_cost_item(const cJSON *line_item, const char* category,
    const char *nickname, GList *list)
{
    g_assert(line_item);
    g_assert(category);

    cJSON *cost_pair = cJSON_GetObjectItem(line_item, category);
    cJSON *amount    = cJSON_GetObjectItem(cost_pair, "amount");
    cJSON *currency  = cJSON_GetObjectItem(cost_pair, "currency");

    if (cost_pair && amount && currency && cJSON_IsNumber(amount) &&
        cJSON_IsString(currency)) {

        gchar *amount_string = g_strdup_printf("%.2f %s", 
            ((float) amount->valueint) / 100, currency->valuestring);

        DBG_LOG("%s: %s", category, amount_string);

        if (!list) {
            g_free(amount_string);

            return NULL; 
        }

        list = list_append_pair(list, nickname, amount_string);

        g_free(amount_string);

        return list; 
    } else {
        DBG_LOG("%s: %s %s", category, "NA", "NA");

        if (!list) {
            return NULL;
        }

        return list_append_pair(list, nickname, "NA");
    }
}

GList * get_line_items(const cJSON *order, const char *order_id,
    const char *utc_time, GList *master_list)
{
    g_assert(order);
    g_assert(order_id);
    g_assert(master_list);

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, cJSON_GetObjectItem(order, "line_items")) {
        
        cJSON *quantity       = cJSON_GetObjectItem(elem, "quantity");
        cJSON *name           = cJSON_GetObjectItem(elem, "name");
        cJSON *variation_name = cJSON_GetObjectItem(elem, "variation_name");
        cJSON *note           = cJSON_GetObjectItem(elem, "note");

        DBG_LOG("%s", "====== LINE ITEM =======");
        if (quantity && name && cJSON_IsString(quantity) &&
            cJSON_IsString(name)) {
            
            char *name_string = NULL;
            if (variation_name) {
                name_string = g_strdup_printf("%s / %s", get_string_safe(name),
                    get_string_safe(variation_name));
            }

            DBG_LOG("Got Quantity %s, Name %s", quantity->valuestring,
                name_string);

            GList *metadata_items = NULL;

            metadata_items = list_append_pair(metadata_items, "Type", 
                "T_LINE_ITEM");

            metadata_items = list_append_pair(metadata_items, "Name", 
                name_string);

            metadata_items = list_append_pair(metadata_items, "Quantity", 
                get_string_safe(quantity));

            metadata_items = list_append_pair(metadata_items, "Note", 
                get_string_safe(note));

            metadata_items = get_cost_item(elem, "total_tax_money", "Tax",
                metadata_items);
        
            metadata_items = get_cost_item(elem, "total_discount_money",
            "Discount", metadata_items);

            metadata_items = get_cost_item(elem, "base_price_money", "Unit Price",
                metadata_items);

            metadata_items = get_cost_item(elem, "total_money", "Total",
                metadata_items);

            /* Put Order ID last as it is long and bulky */
            metadata_items = list_append_pair(metadata_items,
                "OrderID", order_id);

            master_list = g_list_append(master_list, 
                acs_create_sublist(metadata_items, utc_time));

            g_free(name_string);
            
        }
        DBG_LOG("%s", "====== /LINE ITEM ======");
    }

    return master_list;
}

GList * get_discounts(const cJSON *order, const char *order_id,
    const char *utc_time, GList *master_list)
{
    g_assert(order);
    g_assert(order_id);

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, cJSON_GetObjectItem(order, "discounts")) {
        
        cJSON *uid   = cJSON_GetObjectItem(elem, "uid");
        cJSON *name  = cJSON_GetObjectItem(elem, "name");
        cJSON *scope = cJSON_GetObjectItem(elem, "scope"); 

        DBG_LOG("%s", "====== DISCOUNT ITEM =======");
        if (uid && name && scope && cJSON_IsString(uid) &&
            cJSON_IsString(name) && cJSON_IsString(scope)) {
            DBG_LOG("Got Discount name %s, scope=%s, uid=%s", name->valuestring,
                scope->valuestring, uid->valuestring);
        }

        GList *metadata_items = NULL;

        metadata_items = list_append_pair(metadata_items, "Type", "DISCOUNT");

        if (cJSON_HasObjectItem(elem, "applied_money")) {
            metadata_items = get_cost_item(elem, "applied_money", 
                "Discount", metadata_items);
        } else {
            metadata_items = get_cost_item(elem, "amount_money", 
                "Discount", metadata_items);
        }

        metadata_items = list_append_pair(metadata_items, "Name", 
            get_string_safe(name));

        const char *scope_string = strcmp(scope->valuestring, "ORDER") == 0 ? 
            "GLOBAL" : scope->valuestring; 
        metadata_items = list_append_pair(metadata_items, 
            "Scope", scope_string);

        metadata_items = list_append_pair(metadata_items, "OrderID", order_id);

        master_list = g_list_append(master_list, 
                acs_create_sublist(metadata_items, utc_time));

        DBG_LOG("%s", "====== /DISCOUNT ITEM =======");
    }

    return master_list;
}

static const char* get_string_safe(const cJSON *cjs)
{
    if (!cjs || !cJSON_IsString(cjs)) {
        return "NA";
    }

    return cjs->valuestring;
}

static GList * get_card_details(const cJSON *tender, GList *list)
{
    g_assert(tender);
    g_assert(list);

    cJSON *card_details = cJSON_GetObjectItem(tender, "card_details");

    cJSON *status       = cJSON_GetObjectItem(card_details, "status");
    cJSON *entry_method = cJSON_GetObjectItem(card_details, "entry_method");

    cJSON *card         = cJSON_GetObjectItem(card_details, "card");
    cJSON *brand        = cJSON_GetObjectItem(card, "card_brand");
    cJSON *last_4       = cJSON_GetObjectItem(card, "last_4");

    DBG_LOG("%s", "==== CARD DETAILS ====");
    DBG_LOG("status=%s, entry_method=%s, brand=%s, last_4=%s",
        get_string_safe(status), get_string_safe(entry_method),
        get_string_safe(brand), get_string_safe(last_4));
    DBG_LOG("%s", "==== /CARD DETAILS ===");

    list = list_append_pair(list, "Card Status", get_string_safe(status));
    list = list_append_pair(list, "Card Method", get_string_safe(entry_method));
    list = list_append_pair(list, "Card Brand", get_string_safe(brand));
    list = list_append_pair(list, "Card last 4", get_string_safe(last_4));

    return list;
}

static GList * get_cash_details(const cJSON *tender, GList *list)
{
    g_assert(tender);
    g_assert(list);

    cJSON *cash_details = cJSON_GetObjectItem(tender, "cash_details");

    DBG_LOG("%s", "==== CASH DETAILS ====");
    list = get_cost_item(cash_details, "buyer_tendered_money", "Cash Received", 
        list);
    list = get_cost_item(cash_details, "change_back_money", "Cash Change", list);
    DBG_LOG("%s", "==== /CASH DETAILS ===");

    return list;
}

GList * get_tenders(const cJSON *order, const char *order_id,
    const char *utc_time, GList *master_list)
{
    g_assert(order);
    g_assert(order_id);

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, cJSON_GetObjectItem(order, "tenders")) {
        
        cJSON *id    = cJSON_GetObjectItem(elem, "id");
        cJSON *type  = cJSON_GetObjectItem(elem, "type");

        DBG_LOG("%s", "====== TENDER ITEM =======");
        if (id && type && cJSON_IsString(id) && cJSON_IsString(type)) {
            DBG_LOG("Got Tender Type %s, id=%s", type->valuestring,
                id->valuestring);

            GList *metadata_items = NULL;

            metadata_items = list_append_pair(metadata_items, "Type", "TENDER"); 
            metadata_items = list_append_pair(metadata_items, "Source OrderID",
                get_string_safe(id));

            if (strcmp(type->valuestring, "CARD") == 0) {
                metadata_items = list_append_pair(metadata_items, 
                    "Payment Method","CARD");
                metadata_items = get_card_details(elem, metadata_items);
            } else if (strcmp(type->valuestring, "CASH") == 0) {
                metadata_items = list_append_pair(metadata_items, 
                    "Payment Method", "CASH");
                metadata_items = get_cash_details(elem, metadata_items);
            }

            metadata_items = get_cost_item(elem, "amount_money", "Total", 
                metadata_items);

            metadata_items = list_append_pair(metadata_items, "OrderID",
                order_id);

            master_list = g_list_append(master_list, 
                acs_create_sublist(metadata_items, utc_time));

        }

        DBG_LOG("%s", "====== /TENDER ITEM =======");
    }

    return master_list;
}

GList * get_refunds(const cJSON *order, const char *order_id,
    const char *utc_time, GList *master_list)
{
    g_assert(order);
    g_assert(order_id);

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, cJSON_GetObjectItem(order, "refunds")) {
        
        cJSON *tid    = cJSON_GetObjectItem(elem, "transaction_id");
        cJSON *reason = cJSON_GetObjectItem(elem, "reason");
        cJSON *status = cJSON_GetObjectItem(elem, "status");

        DBG_LOG("%s", "====== REFUND ITEM =======");
        if (tid && reason && status && cJSON_IsString(tid) &&
            cJSON_IsString(reason)  && cJSON_IsString(status)) {
            DBG_LOG("Got Return Reason=%s, status=%s, id=%s", reason->valuestring,
                status->valuestring, tid->valuestring);

            GList *metadata_items = NULL;

            metadata_items = list_append_pair(metadata_items, "Type", "REFUND");
            metadata_items = list_append_pair(metadata_items, "Note",
                get_string_safe(reason));
            metadata_items = list_append_pair(metadata_items, "Source OrderID",
                get_string_safe(tid));

            metadata_items = get_cost_item(elem, "amount_money", "Total",
                metadata_items);

            metadata_items = list_append_pair(metadata_items, "OrderID",
                order_id);

            overlay_set_data(ovl_handle, metadata_items, utc_time, "Point of Sale Data");
                metadata_items = g_list_first(metadata_items);

            master_list = g_list_append(master_list, 
                acs_create_sublist(metadata_items, utc_time));

        }

        DBG_LOG("%s", "====== /REFUND ITEM =======");
    }

    return master_list;
}

GList * get_returns(const cJSON *order, const char *order_id,
    const char *utc_time, GList *master_list)
{
    g_assert(order);
    g_assert(order_id);

    const cJSON *returns = cJSON_GetObjectItem(order, "returns");

    if (!returns || !cJSON_IsArray(returns)) {
        DBG_LOG("%s", "No return object found");
        return master_list;
    }

    /* Get the source order ID related to the return */
    cJSON *ret_elem = NULL;
    cJSON_ArrayForEach(ret_elem, returns) {

        const cJSON *source_uid = cJSON_GetObjectItem(ret_elem, "source_order_id");
        if (!source_uid || !cJSON_IsString(source_uid)) {
            continue;
        }

        cJSON *elem = NULL;
        cJSON_ArrayForEach(elem, cJSON_GetObjectItem(ret_elem, "return_line_items")) {
            
            cJSON *name           = cJSON_GetObjectItem(elem, "name");
            cJSON *variation_name = cJSON_GetObjectItem(elem, "variation_name");

            char *name_string = NULL;
            if (variation_name) {
                name_string = g_strdup_printf("%s / %s", get_string_safe(name),
                    get_string_safe(variation_name));
            }

            cJSON *quantity       = cJSON_GetObjectItem(elem, "quantity");
            cJSON *note           = cJSON_GetObjectItem(elem, "note");

            GList *metadata_items = NULL;

            metadata_items = list_append_pair(metadata_items, "Type", "RETURN_ITEM");
            metadata_items = list_append_pair(metadata_items, "Name", name_string);
            metadata_items = list_append_pair(metadata_items, "Quantity",
                get_string_safe(quantity));
            metadata_items = list_append_pair(metadata_items, "Note",
                get_string_safe(note));
            metadata_items = get_cost_item(elem, "total_money", "Total", 
                metadata_items);
            metadata_items = list_append_pair(metadata_items, "OrderID",
                    order_id);
            metadata_items = list_append_pair(metadata_items, "Source OrderID",
                get_string_safe(source_uid));

            DBG_LOG("%s", "====== RETURN ITEM =======");
            DBG_LOG("Got Return Note=%s, name=%s, quantity=%s", get_string_safe(note),
                name_string, get_string_safe(quantity));
            DBG_LOG("%s", "====== /REFUND ITEM =======");

            master_list = g_list_append(master_list, 
                acs_create_sublist(metadata_items, utc_time));

            g_free(name_string);
            
        }
    }

    return master_list;
}

static GList * list_append_pair(GList *list, const char *name, const char *value)
{
    mdp_item_pair *item_pair = g_try_new0(mdp_item_pair, 1);

    item_pair->name  = g_strdup(name);
    item_pair->value = g_strdup(value);

    return g_list_append(list, item_pair);
}

static void child_watch_cb (GPid     pid,
                            gint     status,
                            gpointer user_data)
{
    g_assert(user_data);

    DBG_LOG("Child %" G_PID_FORMAT " exited %s", pid,
             g_spawn_check_exit_status (status, NULL) ? "normally" : "abnormally");

    DBG_LOG("%s", "In user callback");

    gsize length;
    gchar *stdout;
    gboolean start_timer = TRUE;

    GIOChannel *channel = g_io_channel_unix_new(GPOINTER_TO_INT(user_data));

    GIOStatus ret = 
        g_io_channel_read_to_end(channel, &stdout, &length, NULL);


    if (ret != G_IO_STATUS_NORMAL) {
        ERR("Failed to read file!!!");
        goto exit;
    } else {
        DBG_LOG("Got stdout %s, length %u", stdout, length);
    }

    cJSON *cjs = cJSON_Parse(stdout);

    if (!cjs) {
        goto exit;
    }

    char *formatted = cJSON_Print(cjs);
    DBG_LOG("%s", formatted);
    g_free(formatted);

    cJSON *elem = NULL;
    GList *master_list = NULL;
    cJSON_ArrayForEach(elem, cJSON_GetObjectItem(cjs, "orders")) {
        cJSON *id = cJSON_GetObjectItem(elem, "id");

        if (!id || !cJSON_IsString(id)) {
            ERR("Failed to get order ID");
            continue;
        }

        cJSON *state   = cJSON_GetObjectItem(elem, "state");
        cJSON *created = cJSON_GetObjectItem(elem, "created_at");
        cJSON *updated = cJSON_GetObjectItem(elem, "updated_at");
        cJSON *closed  = cJSON_GetObjectItem(elem, "closed_at");

        if (closed) {
            const char *order_close_string = get_string_safe(closed);

            if (strcmp(start_zulu_time, order_close_string) == 0) {
                DBG_LOG("%s", "Skipping already existing order");
                continue;
            }

            g_free(start_zulu_time);
            start_zulu_time = g_strdup(order_close_string);
        }

        char *utc_time = NULL;

        if (created && cJSON_IsString(created)) {
            utc_time = acs_rfc_3339_interpret(created->valuestring);
            DBG_LOG("Converted RFC time: %s to UTC time: %s", created->valuestring,
                utc_time);
        } else {
            ERR("%s", "No valid time stamp found, skip order");
            continue;
        }

        DBG_LOG("Got order ID %s, state=%s, created=%s, updated=%s,\
            closed=%s", id->valuestring, get_string_safe(state),
            get_string_safe(created), get_string_safe(updated),
            get_string_safe(closed));

        GList *metadata_items = NULL;

        metadata_items = list_append_pair(metadata_items, "Type", "ORDER");

        metadata_items = list_append_pair(metadata_items, "State", 
            get_string_safe(state));

        metadata_items = get_cost_item(elem, "total_tax_money", "Tax",
            metadata_items);
        
        metadata_items = get_cost_item(elem, "total_discount_money",
            "Discount", metadata_items);

        metadata_items = get_cost_item(elem, "total_tip_money", "Tip",
            metadata_items);

        metadata_items = get_cost_item(elem, "total_money", "Total",
            metadata_items);

        metadata_items = get_cost_item(elem, "total_service_charge_money", 
            "Service Charge", metadata_items);

        /* Put Order ID last as it is long and bulky */
        metadata_items = list_append_pair(metadata_items,
            "OrderID", id->valuestring);

        /** Map customer name, this could be subject to change so have to ask
          * every time.
          */
        cJSON *customer_id = cJSON_GetObjectItem(elem, "customer_id");
        if (customer_id && cJSON_IsString(customer_id)) {
            char *customer_name = 
                square_get_customer_name(customer_id->valuestring);
            
            metadata_items = list_append_pair(metadata_items, "Customer",
                customer_name);
            metadata_items = list_append_pair(metadata_items, "Customer ID",
                customer_id->valuestring);

            g_free(customer_name);
        }

        overlay_set_data(ovl_handle, metadata_items, utc_time, "Point of Sale Data");
        metadata_items = g_list_first(metadata_items);

        //GList *master_list = NULL;
        master_list        = g_list_append(master_list, 
            acs_create_sublist(metadata_items, utc_time));

        DBG_LOG("%s", "============= LINE ITEMS ==================");
        master_list = get_line_items(elem, id->valuestring, utc_time, master_list);
        DBG_LOG("%s", "============= /LINE ITEMS =================");

        DBG_LOG("%s", "============= DISCOUNTS ===================");
        master_list = get_discounts(elem, id->valuestring, utc_time, master_list);
        DBG_LOG("%s", "============= /DISCOUNTS ==================");

        DBG_LOG("%s", "============= TENDERS =====================");
        master_list = get_tenders(elem, id->valuestring, utc_time, master_list);
        DBG_LOG("%s", "============= /TENDERS ====================");

        DBG_LOG("%s", "============= REFUNDS =====================");
        master_list = get_refunds(elem, id->valuestring, utc_time, master_list);
        DBG_LOG("%s", "============= /REFUNDS ====================");

        DBG_LOG("%s", "============= RETURNS =====================");
        master_list = get_returns(elem, id->valuestring, utc_time, master_list);
        DBG_LOG("%s", "============= /RETURNS ====================");

        g_free(utc_time);
    }

    if (master_list) {
        acs_run_async(acs, master_list, acs_done_callback);
        start_timer = FALSE;
    }

exit:
    if (start_timer) {
        g_timeout_add(SQUARE_REFRESH_TIME, on_timeout, NULL);
    }

    cJSON_Delete(cjs);
    g_io_channel_shutdown(channel, FALSE, NULL);
    g_io_channel_unref(channel);
    g_spawn_close_pid (pid);
    g_free(stdout);
}

void get_square_orders(const char *loc_id)
{
    char *auth      = g_strdup_printf("Authorization: Bearer %s", par_access_token);
    char *json_data = g_strdup_printf("{\
        \"location_ids\": [\"%s\"],\
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
        }},\
    \"return_entries\": false}", par_location_id, start_zulu_time);

    char *args[] = {"curl", "-H", "Square-Version: 2020-12-16",
        "-H", auth, "-H", "Content-Type: application/json",
        "-d", json_data,
        "--max-time", "5",
        "https://connect.squareup.com/v2/orders/search", NULL};
    
    int child_stdout;
    GPid child_pid;
    GError *pipe_error = NULL;

    g_spawn_async_with_pipes (NULL, args, NULL, 
                              G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
                              NULL, NULL, &child_pid, NULL, &child_stdout,
                              NULL, &pipe_error);

    if (pipe_error) {
        ERR("Failed to spawn child process: %s\n", pipe_error->message);
        g_free(pipe_error);
    }

    g_free(auth);
    g_free(json_data);
    g_child_watch_add(child_pid, child_watch_cb, GINT_TO_POINTER(child_stdout));
}

void acs_done_callback(void)
{
    g_timeout_add(SQUARE_REFRESH_TIME, on_timeout, NULL);
}

/**
 * Main entry point for application.
 *
 * @param argc Unused number of arguments received on the command line.
 * @param argv Unused vector of commandline arguments.
 *
 * @return Always returns 0.
 */
int main(int argc, char *argv[])
{
    GError *error = NULL;

    openlog(APP_ID, LOG_PID | LOG_CONS, LOG_USER);
    camera_init(APP_ID, APP_NICE_NAME);

    init_signals();

    start_zulu_time = get_zulu_time();

    LOG("Current Zulu time: %s", start_zulu_time);

    loop       = g_main_loop_new(NULL, FALSE);
    acs        = acs_init();
    ovl_handle = overlay_init();

    char value[50];

    if(camera_param_get("ServerAddress", value, 50)) {
        set_server_address(value);
        LOG("%s", value);
    }

    if(camera_param_get("SourceID", value, 50)) {
        set_source_id(value);
        LOG("%s", value);
    }

    if(camera_param_get("Username", value, 50)) {
        set_username(value);
        LOG("%s", value);
    }

    if(camera_param_get("Password", value, 50)) {
        set_password(value);
        LOG("%s", value);
    }

    if(camera_param_get("Enabled", value, 50)) {
        set_enabled(value);
        LOG("%s", value);
    }

    if(camera_param_get("DebugEnabled", value, 50)) {
        set_debug_enabled(value);
        LOG("%s", value);
    }

    if(camera_param_get("SquareAccessToken", value, 200)) {
        set_access_token(value);
        LOG("%s", value);
    }

    if(camera_param_get("SquareRefreshToken", value, 200)) {
        set_refresh_token(value);
        LOG("%s", value);
    }

    if(camera_param_get("SquareExpiration", value, 200)) {
        set_expiration(value);
        LOG("%s", value);
    }

    if(camera_param_get("SquareLocation", value, 50)) {
        set_location(value);
        LOG("%s", value);
    }

    if(camera_param_get("SquareMerchant", value, 200)) {
        set_merchant_id(value);
        LOG("%s", value);
    }

    camera_param_setCallback("ServerAddress",         set_server_address);
    camera_param_setCallback("SourceID",              set_source_id);
    camera_param_setCallback("Username",              set_username);
    camera_param_setCallback("Password",              set_password);
    camera_param_setCallback("Enabled",               set_enabled);
    camera_param_setCallback("DebugEnabled",          set_debug_enabled);
    camera_param_setCallback("SquareAccessToken",     set_access_token);
    camera_param_setCallback("SquareRefreshToken",    set_refresh_token);
    camera_param_setCallback("SquareExpiration",      set_expiration);
    camera_param_setCallback("SquareLocation",        set_location);
    camera_param_setCallback("SquareMerchant",        set_merchant_id);

    camera_http_setCallback("settings/testreporting", cgi_test_reporting);
    camera_http_setCallback("settings/get",           cgi_settings_get);
    camera_http_setCallback("settings/setcode",       cgi_set_code);
    camera_http_setCallback("settings/getlocations",  cgi_get_locations);

    GList *metadata_items = NULL;

    metadata_items = list_append_pair(metadata_items, "Type", "RETURN_ITEM");
    overlay_set_data(ovl_handle, metadata_items, "test", "Point of Sale Data");
    
    /* Periodically call 'on_timeout()' every 10 seconds */
    g_timeout_add(SQUARE_REFRESH_TIME, on_timeout, NULL);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    loop = NULL;

    LOG("%s", "Exiting application");

    //camera_cleanup();
    //closelog();
    //acs_cleanup(&acs);
    //overlay_cleanup(&ovl_handle);

    g_free(par_location_id);
    g_free(par_access_token);
    g_free(par_refresh_token);
    g_free(par_expiration);
    g_free(par_merchant_id);

    g_free(par_debug_enabled);
    g_free(start_zulu_time);

    /* TODO: This locks the program on termination for some reason.
    ax_event_handler_free(event_handler);
    */

    return 0;
}
