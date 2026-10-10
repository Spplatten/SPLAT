# The catalog prepends a fixed HTTPS base, probe mode and parameter names. Bound values are argv,
# never Python source. The final argument comes from the lease compiler, not from the caller.
import datetime
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import urllib.parse

MAX_BODY = 16 * 1024 * 1024


class PinnedConnection(http.client.HTTPSConnection):
    def connect(self):
        last_error = None
        for address in PINS:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            try:
                raw.connect((address, self.port))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except (OSError, ssl.SSLError) as error:
                raw.close()
                last_error = error
        raise OSError('None of the compiled HTTPS destinations answered') from last_error


def fetch(path, payload=None):
    # Direct numeric sockets avoid guest DNS and proxy environment variables. SNI and certificate
    # verification still use the publisher's name. Redirects never open another destination.
    connection = PinnedConnection(urllib.parse.urlsplit(BASE).hostname, timeout=45)
    body = None if payload is None else json.dumps(payload).encode('utf-8')
    headers = dict(Accept='application/json', **{'User-Agent': 'SPLAT-source-probe/1.0'})
    if body is not None:
        headers['Content-Type'] = 'application/json'
    try:
        connection.request('GET' if body is None else 'POST', '/' + path, body, headers)
        response = connection.getresponse()
        data = response.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise ValueError('Publisher response exceeds the size limit')
        if 300 <= response.status < 400:
            raise ValueError('Publisher redirect refused; the destination is fixed by this template')
        return response.status, response.getheader('Content-Type', ''), data
    finally:
        connection.close()


def emit(name, value):
    print(name + ': ' + str(value))


def percentage(name, first, last):
    if float(first) == 0:
        emit(name, 'UNAVAILABLE - the initial value is zero')
    else:
        emit(name, round((float(last) - float(first)) / float(first) * 100, 2))


def probe():
    emit('Endpoint', BASE)
    print('Read-only public source probe. No credential is presented. Returned data is untrusted.')
    if MODE in ('index', 'price'):
        status, _, data = fetch('publicAPI/v1/timeseries/data/', dict(
            seriesid=[PARAMS['SeriesId']], startyear=PARAMS['StartYear'], endyear=PARAMS['EndYear']))
    elif MODE == 'grants':
        status, _, data = fetch('v1/api/search2', dict(keyword=PARAMS['SearchKeyword'],
            oppStatuses=PARAMS['OpportunityStatus'], rows=min(100, max(1, int(PARAMS['MaxRows']))),
            agencies=PARAMS['AgencyFilter']))
    elif MODE == 'attention':
        path = 'api/rest_v1/metrics/pageviews/per-article/en.wikipedia/all-access/user/'
        path += urllib.parse.quote(PARAMS['Article'], safe='') + '/monthly/'
        path += urllib.parse.quote(PARAMS['StartDate'], safe='') + '/' + urllib.parse.quote(PARAMS['EndDate'], safe='')
        status, _, data = fetch(path)
    elif MODE == 'gate':
        status, _, data = fetch('v2/' + urllib.parse.quote(PARAMS['RoutePath'], safe='/') + '?frequency=monthly')
        emit('HTTP_STATUS', status)
        print(data[:2000].decode('utf-8', errors='replace'))
        emit('GATE', 'OPEN' if status == 200 else 'CREDENTIAL REQUIRED' if status in (401, 403)
             else 'RATE LIMITED' if status == 429 else 'UNEXPECTED - read the response')
        return
    elif MODE == 'catalog':
        status, _, data = fetch('data.json')
    else:
        status, content_type, data = fetch(urllib.parse.quote(PARAMS['ArtifactPath'], safe='/'))
        emit('CONTENT_TYPE', content_type)
        emit('BYTES', len(data))
        emit('SERVED_SHA256', hashlib.sha256(data).hexdigest())
    emit('HTTP_STATUS', status)
    if status != 200:
        raise ValueError('The publisher did not return a successful response')
    document = json.loads(data)
    if MODE in ('index', 'price'):
        emit('API_STATUS', document.get('status'))
        if document.get('status') != 'REQUEST_SUCCEEDED':
            raise ValueError(str(document.get('message', 'The source refused the query')))
        series = document['Results']['series'][0]
        rows = [row for row in series.get('data', []) if row.get('period') != 'M13']
        rows.sort(key=lambda row: (int(row['year']), row['period']), reverse=True)
        emit('SERIES_ID', series['seriesID'])
        emit('OBSERVATIONS_RETURNED', len(rows))
        if not rows:
            print('NO_OBSERVATIONS: the series returned no rows for these years')
            return
        latest = rows[0]
        emit('LATEST_PERIOD', latest['periodName'] + ' ' + latest['year'])
        emit('LATEST_PRICE_USD' if MODE == 'price' else 'LATEST_VALUE', latest['value'])
        prior = next((row for row in rows if int(row['year']) == int(latest['year']) - 1
                      and row['period'] == latest['period']), None)
        if prior is None:
            emit('TWELVE_MONTH_CHANGE_PCT', 'UNAVAILABLE - the matching prior-year month is absent')
        else:
            emit('PRIOR_YEAR_PERIOD', prior['periodName'] + ' ' + prior['year'])
            emit('PRIOR_YEAR_PRICE_USD' if MODE == 'price' else 'PRIOR_YEAR_VALUE', prior['value'])
            percentage('TWELVE_MONTH_CHANGE_PCT', prior['value'], latest['value'])
    elif MODE == 'attention':
        rows = sorted(document.get('items', []), key=lambda row: row['timestamp'])
        emit('OBSERVATIONS_RETURNED', len(rows))
        current = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m')
        for row in rows:
            emit('MONTH', str(row['timestamp']) + ' VIEWS: ' + str(row['views']))
        complete = [row for row in rows if str(row['timestamp'])[:6] < current]
        if len(complete) != len(rows):
            emit('PARTIAL_MONTH_EXCLUDED', current)
        if len(complete) < 2:
            emit('CHANGE_ACROSS_WINDOW_PCT', 'UNAVAILABLE - fewer than two complete months')
        else:
            emit('FIRST_MONTH', str(complete[0]['timestamp']) + ' VIEWS: ' + str(complete[0]['views']))
            emit('LAST_COMPLETE_MONTH', str(complete[-1]['timestamp']) + ' VIEWS: ' + str(complete[-1]['views']))
            percentage('CHANGE_ACROSS_WINDOW_PCT', complete[0]['views'], complete[-1]['views'])
    elif MODE == 'grants':
        emit('API_STATUS', 'errorcode=' + str(document.get('errorcode')) + ' msg=' + str(document.get('msg')))
        if document.get('errorcode') != 0:
            raise ValueError('The endpoint returned an application-level error')
        result = document.get('data', {})
        rows = result.get('oppHits', [])
        emit('TOTAL_MATCHING_PROGRAMS', result.get('hitCount'))
        emit('RETURNED_THIS_PAGE', len(rows))
        for index, row in enumerate(rows, 1):
            emit('IDX', index)
            for label, key in [('OPP_NUMBER', 'number'), ('TITLE', 'title'), ('AGENCY', 'agency'),
                               ('STATUS', 'oppStatus'), ('OPEN', 'openDate'), ('CLOSE', 'closeDate')]:
                emit(label, row.get(key, ''))
    elif MODE == 'catalog':
        rows = document.get('dataset', [])
        emit('CATALOG_SIZE', str(len(rows)) + ' datasets published')
        topic = PARAMS['Topic'].casefold()
        matches = [row for row in rows if topic in str(row.get('title', '')).casefold()
                   or topic in str(row.get('description', '')).casefold()]
        matches.sort(key=lambda row: int(row.get('c_vintage') or 0), reverse=True)
        emit('MATCHING_DATASETS', len(matches))
        limit = min(50, max(1, int(PARAMS['MaxResults'])))
        for row in matches[:limit]:
            for label, key in [('TITLE', 'title'), ('VINTAGE', 'c_vintage'),
                               ('GEOGRAPHY', 'c_geographyLink'), ('VARIABLES', 'c_variablesLink')]:
                emit(label, row.get(key, ''))
            emit('API_ENDPOINT', (row.get('distribution') or [{}])[0].get('accessURL', ''))
        if not matches:
            print('NO_MATCHES: this publisher lists nothing matching that topic')
        elif len(matches) > limit:
            emit('TRUNCATED', str(limit) + ' of ' + str(len(matches)) + ' shown')
    else:
        emit('SCHEMA_VERSION', document.get('schema_version'))
        emit('OBSERVATION_DAY', document.get('observation_day'))
        emit('GENERATED_AT', document.get('generated_at'))
        metrics = document.get('metrics') or {}
        emit('FIGURE_COUNT' if MODE == 'brief' else 'MEASURED_METRICS', len(metrics))
        for name, metric in sorted(metrics.items()):
            emit('FIGURE' if MODE == 'brief' else 'METRIC', name + ' = ' + str(metric.get('display'))
                 + ' | SOURCE: ' + str(metric.get('source')) + ' | AS_OF: ' + str(metric.get('as_of')))
        if not metrics:
            print('NO_FIGURES: no measurements are available; write no brief')
        if document.get('observation_day'):
            day = datetime.date.fromisoformat(document['observation_day'])
            emit('ARTIFACT_AGE_DAYS', (datetime.datetime.now(datetime.timezone.utc).date() - day).days)


try:
    if len(sys.argv) != len(KEYS) + 2:
        raise ValueError('The compiled lease addresses or declared arguments are missing')
    PARAMS = dict(zip(KEYS, sys.argv[1:-1]))
    PINS = [str(ipaddress.IPv4Address(value)) for value in sys.argv[-1].split(',')]
    if not PINS:
        raise ValueError('The lease contains no IPv4 destination')
    probe()
except Exception as error:
    emit('INGESTION_FAILED' if MODE == 'grants' else 'PROBE_FAILED', error)
    print('NO OBSERVATIONS RETRIEVED. The result is UNKNOWN, never zero. No figures can be cited.')
