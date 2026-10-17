# Authority is fixed by the catalog and the admission-time host pin map, never by publisher data.
import datetime
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
import uuid


class PinnedConnection(http.client.HTTPSConnection):
    def connect(self):
        for address in PINS[self.host]:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            try:
                raw.connect((address, 443))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except (OSError, ssl.SSLError):
                raw.close()
        raise ValueError('approved_destination_unavailable')


def read_page(url, limit):
    uri = urllib.parse.urlsplit(url)
    if uri.scheme != 'https' or uri.hostname not in PINS or uri.port not in (None, 443) or uri.username or uri.fragment:
        raise ValueError('destination_refused')
    connection = PinnedConnection(uri.hostname, timeout=8, context=ssl.create_default_context())
    try:
        connection.request('GET', uri.path + ('?' + uri.query if uri.query else ''),
                           headers={'User-Agent': 'SPLAT-RARE/1.0', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            return {'redirect': response.getheader('Location'), 'text': ''}
        if response.status != 200:
            raise ValueError('unexpected_http_status_' + str(response.status))
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            raise ValueError('unsupported_encoding')
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('response_too_large')
        return {'redirect': None, 'text': data.decode('utf-8', errors='strict')}
    finally:
        connection.close()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def bounded_text(value, maximum=16000):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError('invalid_evidence_field')
    return value


def catalog():
    queries = {
        'fitness': 'workout planner', 'nutrition': 'meal planner', 'sleep-wellbeing': 'sleep tracker',
        'health-management': 'medication reminder', 'games': 'offline puzzle games',
        'gaming-companions': 'tabletop campaign tracker', 'education': 'language learning',
        'personal-finance': 'budget planner', 'music-audio': 'music practice',
        'outdoors-hobbies': 'hiking trails', 'travel': 'travel itinerary', 'home-pets': 'pet care',
        'shopping-collecting': 'collection inventory', 'relationships-social': 'couples relationship',
        'shift-scheduling': 'shift planner', 'family-coordination': 'family organizer',
        'photo-organization': 'photo organizer'}
    fields = ('trackId', 'trackName', 'sellerName', 'artistName', 'primaryGenreName', 'trackViewUrl',
              'price', 'currency', 'userRatingCount', 'averageUserRating', 'version')
    cohorts = []
    for identifier, query in queries.items():
        if cohorts:
            time.sleep(3.2)
        response = read_page(ORIGIN + 'search?' + urllib.parse.urlencode(
            dict(country='us', entity='software', limit=10, term=query)), 262144)
        if response['redirect']:
            raise ValueError('redirect_refused')
        page = json.loads(response['text'])
        rows = page.get('results')
        if type(page.get('resultCount')) is not int or not isinstance(rows, list) or page['resultCount'] != len(rows) or len(rows) > 10:
            raise ValueError('invalid_catalog_page')
        items = [{key: row[key] for key in fields if row.get(key) is not None} for row in rows]
        cohorts.append(dict(id=identifier, query=query, observed_at=now(), resultCount=len(items), results=items))
    ended = now()
    if any(row['observed_at'][:10] != ended[:10] for row in cohorts):
        raise ValueError('capture_crossed_utc_midnight')
    return dict(schema_version=1, capture_id=str(uuid.uuid4()), profile='consumer-mobile-v1',
                source='apple_search', storefront='us', completed_at=ended, cohorts=cohorts)


def evidence(app_id):
    if not re.fullmatch(r'[1-9][0-9]{0,19}', app_id):
        raise ValueError('invalid_app_id')
    capture = dict(schema_version=1, capture_id=str(uuid.uuid4()), profile='consumer-evidence-v1',
                   app_id=app_id, storefront='us', kind=MODE)
    if MODE == 'reviews':
        url = ORIGIN + 'us/rss/customerreviews/page=1/id=' + app_id + '/sortby=mostrecent/json'
        result = read_page(url, 262144)
        if result['redirect']:
            raise ValueError('redirect_refused')
        feed = json.loads(result['text'])['feed']
        if feed['id']['label'] != url:
            raise ValueError('review_feed_identity_mismatch')
        entries = feed.get('entry', [])
        if not isinstance(entries, list) or len(entries) > 50:
            raise ValueError('review_page_too_large')
        reviews, seen = [], set()
        for entry in entries:
            identifier = entry['id']['label']
            if not isinstance(identifier, str) or not re.fullmatch(r'[0-9]{1,40}', identifier) or identifier in seen:
                raise ValueError('invalid_review_id')
            seen.add(identifier)
            item = {key: {'label': bounded_text(entry[key]['label'])}
                    for key in ('id', 'updated', 'im:rating', 'im:version', 'title', 'content')}
            if not re.fullmatch('[1-5]', item['im:rating']['label']):
                raise ValueError('invalid_review_rating')
            reviews.append(item)
        capture.update(source='apple_public_reviews', source_url=url, observed_at=now(),
                       feed={'id': {'label': url}, 'entry': reviews})
    elif MODE == 'offers':
        url = ORIGIN + 'us/app/id' + app_id
        result = read_page(url, 2097152)
        if result['redirect']:
            url = urllib.parse.urljoin(url, result['redirect'])
            uri = urllib.parse.urlsplit(url)
            if uri.scheme != 'https' or uri.netloc != 'apps.apple.com' or uri.query or uri.fragment or not re.fullmatch(r'/us/app/[a-z0-9-]+/id' + app_id, uri.path):
                raise ValueError('redirect_refused')
            result = read_page(url, 2097152)
            if result['redirect']:
                raise ValueError('redirect_limit')
        scripts = re.findall(r'<script\b[^>]*\bid=[\"\x27]serialized-server-data[\"\x27][^>]*>(.*?)</script>', result['text'], re.S)
        if len(scripts) != 1:
            raise ValueError('listing_schema_changed')
        pages = [row['data'] for row in json.loads(scripts[0])['data']
                 if str(row.get('data', {}).get('titleOfferDisplayProperties', {}).get('adamId')) == app_id]
        if len(pages) != 1:
            raise ValueError('listing_identity_mismatch')
        page = pages[0]
        sections = [row for row in page['shelfMapping']['information']['items'] if row.get('title') == 'In-App Purchases']
        if len(sections) != 1:
            raise ValueError('offers_not_observed')
        pairs = [row for row in sections[0]['items'] if row.get('$kind') == 'textPair']
        if not 1 <= len(pairs) <= 20:
            raise ValueError('offers_not_observed')
        offers = []
        for pair in pairs:
            label = bounded_text(pair['leadingText'], 256)
            price = bounded_text(pair['trailingText'], 32)
            if not label or not re.fullmatch(r'\$[0-9]{1,7}\.[0-9]{2}', price):
                raise ValueError('invalid_offer')
            offers.append(dict(label=label, price_display=price))
        capture.update(source='apple_store_listing', source_url=url, observed_at=now(),
                       listing_name=bounded_text(page['title'], 256), offers=offers)
    else:
        raise ValueError('unsupported_capture')
    return capture


def main():
    global PINS
    try:
        if len(sys.argv) != (2 if MODE == 'catalog' else 3):
            raise ValueError('lease_host_pins_required')
        PINS = json.loads(sys.argv[-1])
        expected = 'apps.apple.com' if MODE == 'offers' else 'itunes.apple.com'
        if set(PINS) != {expected} or not 1 <= len(PINS[expected]) <= 64:
            raise ValueError('invalid_lease_host_pins')
        PINS = {host: [str(ipaddress.IPv4Address(ip)) for ip in addresses] for host, addresses in PINS.items()}
        if any(not ipaddress.ip_address(ip).is_global for ips in PINS.values() for ip in ips):
            raise ValueError('nonpublic_destination_refused')
        capture = catalog() if MODE == 'catalog' else evidence(sys.argv[1])
        encoded = json.dumps(capture, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode('utf-8')) > 262144:
            raise ValueError('capture_too_large')
        print(encoded)
    except Exception as error:
        print('PROBE_FAILED: consumer_' + MODE + '_unavailable; ' + str(error).replace('\n', ' ').replace('\r', ' ')[:240])


if __name__ == '__main__':
    main()
