from datetime import datetime, timedelta, timezone
import json
import logging
import requests
import time
import os
import azure.functions as func
from azure.eventhub import EventHubProducerClient, EventData
from azure.eventhub.exceptions import EventHubError

## Set up logging
logger = logging.getLogger()

## Environment variables keys
WIZ_CLIENT_ID_KEY = "wiz_client_id"
WIZ_CLIENT_SECRET_KEY = "wiz_secret_key"
WIZ_AUTH_URL_KEY = "wiz_auth_url"
WIZ_API_ENDPOINT_KEY = "wiz_api_endpoint"
EVENTHUB_CONNECTION_STRING_KEY = "eventhub_connection_string"
EVENTHUB_NAME_KEY = "eventhub_name"
ENABLE_ISSUES_KEY = "enable_issues_sending"
ENABLE_VULNERABILITIES_KEY = "enable_vulnerabilities_sending"
ENABLE_AUDIT_LOGS_KEY = "enable_audit_logs_sending"
ISSUES_QUERY_FILTER_KEY = "issues_query_filter"
VULNERABILITIES_QUERY_FILTER_KEY = "vulnerabilities_query_filter"
AUDIT_LOGS_QUERY_FILTER_KEY = "audit_logs_query_filter"
DEBUG_LEVEL_KEY = "debug_level"

## Globals parameters init
WIZ_CLIENT_ID = ""
WIZ_CLIENT_SECRET = ""
WIZ_AUTH_URL = ""
WIZ_API_ENDPOINT = ""
EVENTHUB_CONNECTION_STRING = ""
EVENTHUB_NAME = ""
FUNC_NAME = ""
ENABLE_ISSUES = True
ENABLE_VULNERABILITIES = True
ENABLE_AUDIT_LOGS = True
ISSUES_QUERY_FILTER = ""
VULNERABILITIES_QUERY_FILTER = ""
AUDIT_LOGS_QUERY_FILTER = ""
DEBUG_LEVEL = 20

## Global general params
VERSION = "1.0.0"
INTEGRATION_GUID = "84729e85-48fa-c8fe-3caa-a3f1ac23b201"
INTEGRATION_NAME = "azure-eventhub"
FINDINGS_SIZE_BATCH = 1000
LOG_TYPE_ISSUES = "WizIssues"
LOG_TYPE_VULNS = "WizVulnerabilities"
LOG_TYPE_AUDIT_LOGS = "WizAuditLogs"
FREQUENCY = 15
SUCCESS_MESSAGE = 'Wiz <-> Microsoft Event Hub process has been executed successfully'

## GQL queries
ISSUES_QUERY = """
        query IssuesTable($filterBy: IssueFilters $first: Int $after: String $orderBy: IssueOrder) {
          issues:issuesV2(filterBy: $filterBy first: $first after: $after orderBy: $orderBy) {
            nodes {
              id
              sourceRule{
                __typename
                ... on Control {
                  id
                  name
                  controlDescription: description
                  resolutionRecommendation
                }
                ... on CloudEventRule{
                  id
                  name
                  cloudEventRuleDescription: description
                  sourceType
                  type
                }
                ... on CloudConfigurationRule{
                  id
                  name
                  cloudConfigurationRuleDescription: description
                  remediationInstructions
                  serviceType
                }
              }
              createdAt
              updatedAt
              dueAt
              resolvedAt
              statusChangedAt
              type
              projects {
                id
                name
                slug
                businessUnit
                riskProfile {
                  businessImpact
                }
              }
              status
              severity
              entitySnapshot {
                id
                type
                nativeType
                name
                status
                cloudPlatform
                cloudProviderURL
                providerId
                region
                resourceGroupExternalId
                subscriptionExternalId
                subscriptionName
                subscriptionTags
                tags
                externalId
                createdAt
              }
              serviceTickets {
                externalId
                name
                url
              }
              notes {
                createdAt
                updatedAt
                text
                user {
                  name
                  email
                }
                serviceAccount {
                  name
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
    """

AUDIT_LOGS_QUERY = """
query AuditLogTable($first: Int $after: String $filterBy: AuditLogEntryFilters){
    auditLogEntries(first: $first after: $after filterBy: $filterBy) {
      nodes {
        id
        action
        requestId
        status
        timestamp
        userAgent
        sourceIP
        serviceAccount {
          id
          name
        }
        user {
          id
          name
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
"""

VULNERABILITIES_QUERY = """
query VulnerabilityFindingsPage($filterBy: VulnerabilityFindingFilters $first: Int $after: String $orderBy: VulnerabilityFindingOrder) {
  vulnerabilityFindings(filterBy: $filterBy first: $first after: $after orderBy: $orderBy) {
    nodes {
      id
      portalUrl
      name
      CVEDescription
      CVSSSeverity
      score
      exploitabilityScore
      impactScore
      hasExploit
      hasCisaKevExploit
      status
      vendorSeverity
      firstDetectedAt
      lastDetectedAt
      resolvedAt
      description
      remediation
      detailedName
      version
      fixedVersion
      detectionMethod
      link
      locationPath
      resolutionReason
      validatedInRuntime
      epssSeverity
      epssPercentile
      epssProbability
      layerMetadata{
        id
        details
        isBaseLayer
      }
      projects {
        id
        name
        slug
        businessUnit
        riskProfile {
          businessImpact
        }
        projectOwners{
          email
        }
      }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          type
          name
          region
          providerUniqueId
          cloudProviderURL
          cloudPlatform
          status
          subscriptionName
          subscriptionExternalId
          subscriptionId
          tags
          hasLimitedInternetExposure
          hasWideInternetExposure
          isAccessibleFromVPN
          isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions
        }
        ... on VulnerableAssetVirtualMachine {
          operatingSystem
          ipAddresses
        }
        ... on VulnerableAssetServerless {
          runtime
        }
        ... on VulnerableAssetContainerImage {
          imageId
        }
        ... on VulnerableAssetContainer {
          ImageExternalId
          VmExternalId
          ServerlessContainer
          PodNamespace
          PodName
          NodeName
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


class WizApi:
    AUTH0_URLS = ['https://auth.wiz.io/oauth/token', 'https://auth0.gov.wiz.io/oauth/token']
    COGNITO_URLS = ['https://auth.app.wiz.io/oauth/token', 'https://auth.gov.wiz.io/oauth/token',
                    'https://auth.test.wiz.io/oauth/token', 'https://auth.demo.wiz.io/oauth/token']
    ISSUES_EVENT_TYPE = 'issues'
    VULNS_EVENT_TYPE = 'vulnerabilityFindings'
    VULNS_EVENT_TYPE_RES = 'resolved vulnerabilityFindings'
    AUDIT_LOGS_EVENT_TYPE = 'auditLogEntries'
    INIT_ISSUES_VARIABLES = {"first": 500}
    INIT_VULNS_VARIABLES = {"first": 1000}
    INIT_AUDIT_VARIABLES = {"first": 500}
    STATUS_CHANGED = 'statusChangedAt'
    FIRST_SEEN = 'firstSeenAt'
    RESOLVED_AT = 'resolvedAt'
    TIMESTAMP = 'timestamp'
    MAX_RETRIES = 3
    RETRY_TIME = 30
    URL = 'https://app.wiz.io'

    def init(self):
        logging.debug(f'Getting a token, auth URL = {WIZ_AUTH_URL}')
        auth_data = self.select_authentication_provider()
        response = requests.post(
            WIZ_AUTH_URL,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': get_integration_user_agent()
            },
            data=auth_data
        )
        if response.status_code != requests.codes.ok:
            raise Exception(f'Error authenticating to Wiz [{response.status_code}] - {response.text}')
        response_json = response.json()
        access_token = response_json.get('access_token')
        if not access_token:
            raise Exception(f'Could not retrieve token from Wiz: {response_json.get("message")}')
        logging.info('Successfully authenticated to Wiz')
        return access_token

    def select_authentication_provider(self):
        if WIZ_AUTH_URL in self.AUTH0_URLS:
            return {
                'grant_type': 'client_credentials',
                'audience': 'beyond-api',
                'client_id': WIZ_CLIENT_ID,
                'client_secret': WIZ_CLIENT_SECRET
            }
        elif WIZ_AUTH_URL in self.COGNITO_URLS:
            return {
                'grant_type': 'client_credentials',
                'audience': 'wiz-api',
                'client_id': WIZ_CLIENT_ID,
                'client_secret': WIZ_CLIENT_SECRET
            }
        else:
            raise Exception('Invalid Auth URL')

    def get_entries(self, session, query, variables, data_type):
        try:
            logging.debug('Sending a request to Wiz API with\n'
                          f'api_endpoint = {WIZ_API_ENDPOINT}\n'
                          f'query = {query}\n'
                          f'variables = {variables}')
            response = session.post(WIZ_API_ENDPOINT,
                                    json={
                                        'variables': variables,
                                        'query': query
                                    }
                                    )
            logger.debug(f"Response is {response}")
            # Retry mechanism for throttling issues
            retries = 1
            while response.status_code == requests.codes.too_many_requests and retries <= self.MAX_RETRIES:
                logger.info(
                    f'Got throttling exception from Wiz API in attemp number {retries}. Waiting for {self.RETRY_TIME} seconds before trying again')
                time.sleep(self.RETRY_TIME)
                response = session.post(WIZ_API_ENDPOINT,
                                        json={
                                            'variables': variables,
                                            'query': query
                                        }
                                        )
                retries = retries + 1

            if retries >= self.MAX_RETRIES:
                raise Exception(
                    'Got too many throttling errors from Wiz [{}] - {}'.format(response.status_code, response.text))
            if response.status_code != requests.codes.ok:
                raise Exception('Error authenticating to Wiz [{}] - {}'.format(response.status_code, response.text))
            response_json = response.json()
            data = response_json.get('data')
            logger.debug(f'Response: {json.dumps(data)}')
            if not data:
                raise Exception('Could not get entries from Wiz: {}'.format(response_json.get('errors')))
            logging.debug('Request sent successfully and received response with data')
            return data[data_type]['nodes'], data[data_type]['pageInfo']
        except Exception as e:
            logger.error(f"Received an error while performing an API call to Wiz."
                         f"Error info: {str(e)}")
            raise e

    def query(self, session, query, variables, data_type):
        entries, page_info = self.get_entries(session, query, variables, data_type)

        while page_info['hasNextPage']:
            logging.debug(f'Fetch {data_type} from next page')
            variables['after'] = page_info['endCursor']
            new_entries, page_info = self.get_entries(session, query, variables, data_type)
            if new_entries is not None:
                entries += new_entries
        return entries


def get_vars(timestamp, init_vars, filter_property, query_filters):
    res = init_vars
    timestamp_obj = {filter_property:{
        'after': timestamp
    }
    }
    res['filterBy'] = timestamp_obj
    if query_filters and isinstance(query_filters, dict):
        res['filterBy'].update(query_filters)
    return res

def get_query_variables(data_type):
    d = datetime.today().astimezone(timezone.utc) - timedelta(hours=0, minutes=int(FREQUENCY))
    latest_timestamp = d.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    logger.info(f'Going to fetch all {data_type} which updated since {latest_timestamp}')
    variables = {}
    if data_type == WizApi.ISSUES_EVENT_TYPE:
        variables = get_vars(latest_timestamp, WizApi.INIT_ISSUES_VARIABLES, WizApi.STATUS_CHANGED, ISSUES_QUERY_FILTER)
    if data_type == WizApi.VULNS_EVENT_TYPE:
        variables = get_vars(latest_timestamp, WizApi.INIT_VULNS_VARIABLES, WizApi.FIRST_SEEN, VULNERABILITIES_QUERY_FILTER)
    if data_type == WizApi.VULNS_EVENT_TYPE_RES:
        variables = get_vars(latest_timestamp, WizApi.INIT_VULNS_VARIABLES, WizApi.RESOLVED_AT, VULNERABILITIES_QUERY_FILTER)
    if data_type == WizApi.AUDIT_LOGS_EVENT_TYPE:
        variables = get_vars(latest_timestamp, WizApi.INIT_AUDIT_VARIABLES, WizApi.TIMESTAMP, AUDIT_LOGS_QUERY_FILTER)
    if 'after' in variables:
        variables.pop('after')
    logger.info(f'variables for the query: {variables}')
    return variables


def send_data_to_eventhub(events, log_type, producer_client):
    """
    Send data to Azure Event Hub
    """
    try:
        # Create event data batch
        event_data_batch = producer_client.create_batch()
        
        # Add events to the batch
        for event in events:
            # Add metadata to each event
            event_with_metadata = {
                "log_type": log_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": event
            }
            
            # Convert to JSON string
            event_json = json.dumps(event_with_metadata)
            event_data = EventData(event_json)
            event_data_batch.add(event_data)
        
        # Send the batch
        producer_client.send_batch(event_data_batch)
        logger.info(f'Successfully posted {len(events)} events to Azure Event Hub')
        return True
        
    except EventHubError as e:
        logger.error(f"EventHubError occurred while sending data to Event Hub: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error occurred while sending data to Event Hub: {str(e)}")
        return False


def get_log_type(data_type):
    if data_type == WizApi.ISSUES_EVENT_TYPE:
        return LOG_TYPE_ISSUES
    if data_type == WizApi.VULNS_EVENT_TYPE:
        return LOG_TYPE_VULNS
    if data_type == WizApi.AUDIT_LOGS_EVENT_TYPE:
        return LOG_TYPE_AUDIT_LOGS


def post_findings_to_eventhub(findings, producer_client, data_type):
    total_success = True
    log_type = get_log_type(data_type)
    
    # Split findings into batches to avoid overwhelming the Event Hub
    num_of_findings = len(findings)
    num_of_batches = (int)(num_of_findings / FINDINGS_SIZE_BATCH)
    
    for i in range(num_of_batches):
        start_idx = i * FINDINGS_SIZE_BATCH
        end_idx = ((i + 1) * FINDINGS_SIZE_BATCH)
        logger.debug(f'trying to send {data_type} findings to Event Hub. range: {start_idx} - {end_idx}')
        temp_success = send_data_to_eventhub(findings[start_idx:end_idx], log_type, producer_client)
        if not temp_success:
            total_success = False

    if num_of_findings % FINDINGS_SIZE_BATCH != 0:
        logger.debug(
            f'trying to send {data_type} findings to Event Hub. range: {num_of_batches * FINDINGS_SIZE_BATCH} - {len(findings)}')
        temp_success = send_data_to_eventhub(findings[num_of_batches * FINDINGS_SIZE_BATCH:], log_type, producer_client)
        if not temp_success:
            total_success = False

    return total_success


def convert_to_bool(str):
    if str.lower().strip() == "true".lower().strip():
        return True
    if str.lower().strip() == "false".lower().strip():
        return False
    raise Exception(f'{str} is not convertible to boolean')


def init_parameters_from_app_config():
    global WIZ_CLIENT_SECRET, WIZ_CLIENT_ID, WIZ_AUTH_URL, WIZ_API_ENDPOINT, EVENTHUB_CONNECTION_STRING, EVENTHUB_NAME
    global ENABLE_ISSUES, ENABLE_VULNERABILITIES, ENABLE_AUDIT_LOGS, ISSUES_QUERY_FILTER, VULNERABILITIES_QUERY_FILTER, AUDIT_LOGS_QUERY_FILTER
    global DEBUG_LEVEL, logger
    
    WIZ_CLIENT_ID = os.environ[WIZ_CLIENT_ID_KEY]
    WIZ_CLIENT_SECRET = os.environ[WIZ_CLIENT_SECRET_KEY]
    WIZ_AUTH_URL = os.environ[WIZ_AUTH_URL_KEY]
    WIZ_API_ENDPOINT = os.environ[WIZ_API_ENDPOINT_KEY]
    EVENTHUB_CONNECTION_STRING = os.environ[EVENTHUB_CONNECTION_STRING_KEY]
    EVENTHUB_NAME = os.environ[EVENTHUB_NAME_KEY]
    ENABLE_ISSUES = convert_to_bool(os.environ[ENABLE_ISSUES_KEY])
    ENABLE_VULNERABILITIES = convert_to_bool(os.environ[ENABLE_VULNERABILITIES_KEY])
    ENABLE_AUDIT_LOGS = convert_to_bool(os.environ[ENABLE_AUDIT_LOGS_KEY])
    DEBUG_LEVEL = int(os.environ[DEBUG_LEVEL_KEY])
    logger.setLevel(DEBUG_LEVEL)
    
    temp = os.getenv(ISSUES_QUERY_FILTER_KEY)
    if temp:
        ISSUES_QUERY_FILTER = json.loads(temp)
        logger.info(f'Issues query filter in dict: {ISSUES_QUERY_FILTER}')
    temp = os.getenv(VULNERABILITIES_QUERY_FILTER_KEY)
    if temp:
        VULNERABILITIES_QUERY_FILTER = json.loads(temp)
        logger.info(f'Vulnerabilities query filter in dict: {VULNERABILITIES_QUERY_FILTER}')
    temp = os.getenv(AUDIT_LOGS_QUERY_FILTER_KEY)
    if temp:
        AUDIT_LOGS_QUERY_FILTER = json.loads(temp)
        logger.info(f'Audit Logs query filter in dict: {AUDIT_LOGS_QUERY_FILTER}')
    
    logger.info(f'Successfully retrieved all the parameters and credentials from Azure Function App environment,'
                f'send issues = {ENABLE_ISSUES}, send vulnerabilities = {ENABLE_VULNERABILITIES}, send audit logs = {ENABLE_AUDIT_LOGS}')


def add_url_issues(issues):
    try:
        for item in issues:
            item['sourceURL'] = f"{WizApi.URL}/issues#~(issue~'{item['id']})"
    except Exception as e:
        error_message = f"Exception encountered when trying to add issue URL. {e}"
        logger.error(error_message)
        raise Exception(error_message)


def update_tags_fields(findings, asset_object_name, tags_field_name):
    for finding in findings:
        asset = finding[asset_object_name]
        if tags_field_name in asset:
            tags_obj = asset.get(tags_field_name, None)
            if tags_obj is not None and len(tags_obj) > 0 and isinstance(tags_obj, dict):
                tags_as_list = []
                for k, v in tags_obj.items():
                    val = v if v is not None else ""
                    val = val if isinstance(val, str) else str(val)
                    key = k if k is not None else ""
                    key = key if isinstance(key, str) else str(key)
                    tags_as_list.append({key: val})
                finding[asset_object_name][tags_field_name] = tags_as_list


def get_data_and_send_to_eventhub(session, producer_client, data_type):
    variables = get_query_variables(data_type)
    logger.debug(f'Fetching {data_type}, query variables = {variables}')
    
    if data_type == WizApi.ISSUES_EVENT_TYPE:
        findings = WIZ_API_CLIENT.query(session, ISSUES_QUERY, variables, data_type)
        add_url_issues(findings)
        update_tags_fields(findings, 'entitySnapshot', 'tags')
        update_tags_fields(findings, 'entitySnapshot', 'subscriptionTags')
    if data_type == WizApi.VULNS_EVENT_TYPE:
        findings = WIZ_API_CLIENT.query(session, VULNERABILITIES_QUERY, variables, data_type)
        variables = get_query_variables(WizApi.VULNS_EVENT_TYPE_RES)
        findings += WIZ_API_CLIENT.query(session, VULNERABILITIES_QUERY, variables, data_type)
        update_tags_fields(findings, 'vulnerableAsset', 'tags')
    if data_type == WizApi.AUDIT_LOGS_EVENT_TYPE:
        findings = WIZ_API_CLIENT.query(session, AUDIT_LOGS_QUERY, variables, data_type)
    
    logger.info(f"Fetched {len(findings)} {data_type} from Wiz API")

    if not findings:
        logger.info(f'There were no {data_type} updates in your Wiz tenant, nothing to push to Event Hub')
        return True

    return post_findings_to_eventhub(findings, producer_client, data_type)


def execute_flow_by_data_type(session, producer_client):
    total_success = True
    if ENABLE_ISSUES:
        temp_success = get_data_and_send_to_eventhub(session, producer_client, WizApi.ISSUES_EVENT_TYPE)
        if not temp_success:
            total_success = False
    if ENABLE_VULNERABILITIES:
        temp_success = get_data_and_send_to_eventhub(session, producer_client, WizApi.VULNS_EVENT_TYPE)
        if not temp_success:
            total_success = False
    if ENABLE_AUDIT_LOGS:
        temp_success = get_data_and_send_to_eventhub(session, producer_client, WizApi.AUDIT_LOGS_EVENT_TYPE)
        if not temp_success:
            total_success = False
    return total_success


def get_integration_user_agent():
    integration_user_agent = f'{INTEGRATION_GUID}/{INTEGRATION_NAME}/{VERSION}'
    return integration_user_agent


WIZ_API_CLIENT = WizApi()


def main(mytimer: func.TimerRequest, context: func.Context) -> None:
    global FUNC_NAME
    FUNC_NAME = context.function_name
    logger.info(f'Starting Wiz <> Event Hub Execution. Func name = {FUNC_NAME}. Version = {VERSION}')
    
    try:
        init_parameters_from_app_config()
    except Exception as ex:
        error_msg = f"Error while attempting to get environment variables from Azure Function App environment.\nError " \
                    f"details: {ex}"
        logger.error(error_msg)
        raise Exception(error_msg)

    try:
        wiz_token = WIZ_API_CLIENT.init()
        logger.debug('successfully got Wiz token')
    except Exception as ex:
        error_msg = f"Error while attempting to get Wiz Secrets.\nError details: {ex}"
        logger.error(error_msg)
        return

    # Create Event Hub producer client
    try:
        producer_client = EventHubProducerClient.from_connection_string(
            conn_str=EVENTHUB_CONNECTION_STRING,
            eventhub_name=EVENTHUB_NAME
        )
        logger.debug('Successfully created Event Hub producer client')
    except Exception as ex:
        error_msg = f"Error while creating Event Hub producer client.\nError details: {ex}"
        logger.error(error_msg)
        return

    with requests.Session() as session:
        session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + wiz_token,
            'User-Agent': get_integration_user_agent()
        })
        
        try:
            total_success = execute_flow_by_data_type(session, producer_client)

            if total_success:
                logger.info(SUCCESS_MESSAGE)
            else:
                logger.warning(
                    f'{SUCCESS_MESSAGE} - errors occurred in sending Wiz data to Event Hub, check the logs for more '
                    f'details')

        except Exception as ex:
            error_msg = f"Error while attempting to get Wiz data and push it to Azure Event Hub.\nError details: {ex}"
            logger.error(error_msg)
            raise Exception(error_msg)
        finally:
            # Close the producer client
            producer_client.close()
