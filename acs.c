#include <glib.h>
#include <glib-object.h>
#include <glib/gprintf.h>

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acs.h"
#include "acs_commands.h"
#include "metadata_pair.h"
#include "debug.h"

/** @file acs.c
 * @Brief Implementation file for abstraction of ACS metadata API integration.
 *
 * Handle ACS communication, generate JSON data structes and send the
 * commands using cURL to the ACS server. Provide methods of error checking
 * the communication.
 */

/******************** MACRO DEFINITION SECTION ********************************/


/******************** LOCAL VARIABLE DECLARATION SECTION **********************/

typedef struct acs
{
    gchar *username;
    gchar *password;    
    gchar *ipname;
    gchar *source;
    gchar *enabled;
} acs;

typedef struct acs_sublist
{
    GList *list;
    char *utc_time;
} acs_sublist;

typedef struct async_data
{
    GList *cur_list;
    int fd;
    acs_handle handle;
    acs_callback_func cb;
} async_data;

/******************** LOCAL FUNCTION DECLARATION SECTION **********************/

/**
 * Check for JSON error messages when sending ACS command.
 *
 * @param buffer String containing stdout contents from the cURL system call.
 * @param error  Mandatory location to place error message.
 *
 * @return TRUE on success, FALSE on any error.
 */
static gboolean check_jSON_response(const char *buffer, char **error);

static gboolean is_initialized(const acs_handle handle);

static acs_handle copy_handle(const acs_handle handle);

static void destroy_sublist(gpointer data);


/******************** LOCAL FUNCTION DEFINTION SECTION ************************/

static void destroy_sublist(gpointer data) 
{
    if (!data) {
        return;
    }

    acs_sublist *sublist = data;

    mdp_destroy_list(&sublist->list);
    g_free(sublist->utc_time);
    g_free(data);
}

/**
 * Check for JSON error messages when sending ACS command.
 */
static gboolean check_jSON_response(const char *buffer, char **error)
{
    g_assert(error);

    gboolean ret = FALSE;

    if (buffer) {
        gchar http_code[4];
        gchar *code_start = g_strrstr(buffer, "HTTP");

        if (code_start) {
            int hits = sscanf(code_start, "HTTP:%3s", http_code);
            DBG_LOG("Got HTTP code %s", http_code);

            if (hits == 1) {
                if (g_strcmp0(http_code, "200") == 0) {
                    ret = TRUE;
                } else if (g_strcmp0(http_code, "000") == 0) {
                    *error = g_strdup("Bad IP:Port");
                } else if (g_strcmp0(http_code, "401") == 0) {
                    *error = g_strdup("Unauthorized");
                } else if (g_strcmp0(http_code, "400") == 0) {
                    *error = g_strdup("Bad source ID");
                }
            } 
        }
    }

    if (*error == NULL) {
        *error = g_strdup("Unknown Error");
    }

    return ret;
}

static gboolean is_initialized(const acs_handle handle)
{
    if (handle == NULL) {
        return FALSE;
    }

    if (handle->enabled == NULL || g_strcmp0(handle->enabled, "yes") != 0) {
        return FALSE;
    }

    if (handle->username == NULL) {
        return FALSE;
    }

    if (handle->password == NULL) {
        return FALSE;
    }

    if (handle->ipname == NULL) {
        return FALSE;
    }

    if (handle->source == NULL) {
        return FALSE;
    }

    return TRUE;
}

static acs_handle copy_handle(const acs_handle handle)
{
    acs_handle new_handle = acs_init();

    if (!new_handle) {
        return NULL;
    }

    new_handle->username = g_strdup(handle->username);
    new_handle->password = g_strdup(handle->password);
    new_handle->ipname   = g_strdup(handle->ipname);
    new_handle->source   = g_strdup(handle->source);
    new_handle->enabled  = g_strdup(handle->enabled);

    return new_handle;
}

/******************** GLOBAL FUNCTION DEFINTION SECTION ***********************/

acs_sublist_handle acs_create_sublist(GList *list, const char *utc_time)
{
    acs_sublist_handle handle  = g_new0(acs_sublist, 1);

    handle->list     = list;
    handle->utc_time = g_strdup(utc_time);

    return handle; 
}

/**
 * Initialize MDP information
 */
acs_handle acs_init()
{
    acs_handle handle = g_new0(acs, 1);

    return handle;
}

/**
 * Cleanup MDP
 */
void acs_cleanup(acs_handle *handle_p)
{
    if (handle_p == NULL) {
        return;
    }

    if (*handle_p == NULL) {
        return;
    }

    acs_handle handle = *handle_p;

    g_free(handle->username);
    g_free(handle->password);
    g_free(handle->ipname);
    g_free(handle->source);
    g_free(handle->enabled);

    g_free(handle);

    handle_p = NULL;
}

static void child_watch_cb(GPid     pid,
                           gint     status,
                           gpointer user_data)
{
    g_assert(user_data);

    LOG("Child %" G_PID_FORMAT " exited %s", pid,
             g_spawn_check_exit_status (status, NULL) ? "normally" : "abnormally");

    LOG("In user callback");

    GError *error = NULL;
    gsize length;
    gchar *stdout = NULL;
    
    /* Get user data */
    async_data *data     = (async_data *) user_data;
    GList *list          = data->cur_list;
    int fd               = data->fd;
    acs_handle handle    = data->handle; 

    GIOChannel *channel = g_io_channel_unix_new(fd);

    GIOStatus ret = 
        g_io_channel_read_to_end(channel, &stdout, &length, &error);

    if (ret != G_IO_STATUS_NORMAL) {
        ERR("Failed to read file!!!");
        goto cleanup;
    } else {
        LOG("Got stdout %s, length %u", stdout, length);
    }

cleanup:
    g_io_channel_shutdown(channel, FALSE, &error);
    g_spawn_close_pid(pid);
    g_free(stdout);
    g_free(error);

    if (list->next != NULL) {
        LOG("Have more items to send, progress to next");
        acs_run_async(handle, list->next, data->cb);
    } else {
        LOG("Reached end of list, finalize");
        g_list_free_full(g_list_first(list), destroy_sublist);
        data->cb();
    }

    acs_cleanup(&handle);
    g_free(user_data);
}

void acs_run_async(const acs_handle handle,
                   GList *master_list,
                   acs_callback_func cb)
{
    gchar *jSON_string    = NULL;
    gchar *tmp_concat     = NULL;
    gchar *url            = NULL;
    gchar *creds          = NULL;
    GList *metadata_items = NULL; 

    if (is_initialized(handle) == FALSE) {
        ERR("ACS called unitiated");
        cb();
        goto cleanup;
    }

    LOG("CALLING ACS RUN ASYNC");

    if (!master_list || !master_list->data) {
        ERR("ACS acs_run_async called with bad list");
        cb();
        goto cleanup;
    }

    acs_sublist *sublist = master_list->data;
    metadata_items       = sublist->list;
    char *utc_time       = sublist->utc_time;

    LOG("GOT UTC %s", utc_time);

    /* Boilerplate JSON command structure */
    jSON_string = g_strdup_printf(\
        "{ \
            \"addExternalDataRequest\": \
                { \"occurrenceTime\": \"%s\",\
                  \"source\": \"%s\",\
                  \"externalDataType\": \
                  \"PointOfSales\", \"data\": {", utc_time, handle->source);

    GList *list = metadata_items;
    for (; list != NULL; list = list->next) {
        /* Create JSON data entry and append to jSON string */
        mdp_item_pair *item_pair = list->data;
        gchar *item_string = g_strdup_printf("\"%s\":\"%s\",",
            item_pair->name, item_pair->value);

        LOG("Got MDP Item pair %s", item_string);

        tmp_concat = g_strconcat(jSON_string, item_string, NULL);
        
        g_free(item_string);
        g_free(jSON_string);
        
        jSON_string = tmp_concat;
    }

    tmp_concat = g_strconcat(jSON_string, "}}}", NULL);
    g_free(jSON_string);
    jSON_string = tmp_concat;

    url = g_strdup_printf("https://%s/Acs/Api/ExternalDataFacade/AddExternalData",
        handle->ipname);
    creds = g_strdup_printf("%s:%s", handle->username, handle->password);
    char *args[] = {"curl", "--insecure", "--anyauth", "-H", 
        "Content-Type: application/json", "--max-time", "2", "--data",
        jSON_string, "--max-time", "2",
        url, "--user", creds, NULL};
    
    int child_stdout;
    GPid child_pid;
    GError *pipe_error = NULL;

    g_spawn_async_with_pipes (NULL, args, NULL, 
                              G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
                              NULL, NULL, &child_pid, NULL, &child_stdout,
                              NULL, &pipe_error);

    if (pipe_error) {
        ERR("Failed to spawn child process: %s\n", pipe_error->message);
        cb();
        g_free(pipe_error);
    }

    async_data *user_data = g_try_new0(async_data, 1);
    user_data->cur_list   = master_list;
    user_data->fd         = child_stdout;
    user_data->handle     = copy_handle(handle);
    user_data->cb         = cb;

    g_child_watch_add(child_pid, child_watch_cb, user_data);

cleanup:
    g_free(url);
    g_free(creds);
    g_free(jSON_string);
}    


/**
*  Send Metadata to ACS
*/
gboolean acs_run(const acs_handle handle,
                 GList *metadata_items,
                 char **error,
                 const char *utc_time)
{
    gchar **data_items  = NULL;
    gchar *jSON_string  = NULL;
    gchar *tmp_concat   = NULL;
    GList *overlay_data = NULL;

    char *cmd    = NULL;
    gboolean ret = TRUE;

    if (is_initialized(handle) == FALSE) {
        if (error) {
            *error = g_strdup("Missing config");
        }
        return FALSE;
    }

    /* Boilerplate JSON command structure */
    jSON_string = g_strdup_printf(\
        "{ \
            \"addExternalDataRequest\": \
                { \"occurrenceTime\": \"%s\",\
                  \"source\": \"%s\",\
                  \"externalDataType\": \
                  \"PointOfSales\", \"data\": {", utc_time, handle->source);

    GList *list = metadata_items;
    for (; list != NULL; list = list->next) {
        /* Create JSON data entry and append to jSON string */
        mdp_item_pair *item_pair = list->data;
        gchar *item_string = g_strdup_printf("\"%s\":\"%s\",",
            item_pair->name, item_pair->value);

        LOG("Got MDP Item pair %s", item_string);

        overlay_data = g_list_append(
            overlay_data, g_strdup(item_string));

        tmp_concat = g_strconcat(jSON_string, item_string, NULL);
        
        g_free(item_string);
        g_free(jSON_string);
        
        jSON_string = tmp_concat;
    }

    tmp_concat = g_strconcat(jSON_string, "}}}", NULL);
    g_free(jSON_string);
    jSON_string = tmp_concat;
    
    cmd = g_strdup_printf(METABASE, jSON_string, handle->ipname,
                          handle->username, handle->password);

    /**
     * Only perform blocking call if we are checking for error (test reporting).
     * We need to perform a non-blocking call during normal operation because
     * this function will be run in the GMainLoop context.
     *
     * TODO: Look at using worker threads, libcurl etc. if we want error
     * checking for each metadata upload. Possible create an event so user can
     * be notified of reporting errors.
     */
    if (error) {
        gchar *stdout;
        gchar *stderr;
        
        (void) g_spawn_command_line_sync(cmd, 
            &stdout, &stderr, NULL, NULL);

        ret = check_jSON_response(stdout, error);

        g_free(stdout);
        g_free(stderr);
    } else {
        /* Send JSON command, return value is not useful */
        (void) g_spawn_command_line_async(cmd, NULL);
    }

cleanup:
    g_free(jSON_string);
    g_strfreev(data_items);    
    g_free(cmd);

    return ret;
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
void acs_set_username(const acs_handle handle, const char *username)
{
    if (handle == NULL) {
        return;
    }

    g_free(handle->username);
    handle->username = g_strdup(username);
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
void acs_set_password(const acs_handle handle, const char *password)
{
    if (handle == NULL) {
        return;
    }

    g_free(handle->password);
    handle->password = g_strdup(password);
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
void acs_set_ipname(const acs_handle handle, const char *ipname)
{
    if (handle == NULL) {
        return;
    }

    g_free(handle->ipname);
    handle->ipname = g_strdup(ipname);
}


/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
void acs_set_source(const acs_handle handle, const char *source)
{
    if (handle == NULL) {
        return;
    }

    g_free(handle->source);
    handle->source = g_strdup(source);    
}

void acs_set_enabled(const acs_handle handle, const char *enabled)
{
    if (handle == NULL) {
        return;
    }

    g_free(handle->enabled);
    handle->enabled = g_strdup(enabled);
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
const char * acs_get_username(const acs_handle handle)
{
    if (handle == NULL) {
        return NULL;
    }

    return handle->username;
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
const char * acs_get_password(const acs_handle handle)
{
    if (handle == NULL) {
        return NULL;
    }

    return handle->password;
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
const char * acs_get_ipname(const acs_handle handle)
{
    if (handle == NULL) {
        return NULL;
    }

    return handle->ipname;
}

/**
 * Initialize Metadata Push framework.
 *
 * @param username  Username for the ACS server.
 * @param password  Password for the ACS server.
 * @param acs_ip    IP Address for the ACS server.
 * @param source_id Source Key to use for the Metadata.
 *
 * @return No return value.
 */
const char * acs_get_source(const acs_handle handle)
{
    if (handle == NULL) {
        return NULL;
    }

    return handle->source;
}

const char * acs_get_enabled(const acs_handle handle)
{
    if (handle == NULL) {
        return NULL;
    }

    return handle->enabled;
}

char *acs_rfc_3339_interpret(const char *rfc)
{
    char date[10+1];
    char time[12+1];

    int matches = sscanf(rfc, "%10sT%12sZ", date, time);

    if (matches != 2) {
        ERR("Failed to convert RFC to ACS UTC time string");
        return NULL;
    }

    return g_strdup_printf("%s %s", date, time);
} 