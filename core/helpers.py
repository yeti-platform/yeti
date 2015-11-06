import re

tlds = ['abb', 'abbott', 'abogado', 'ac', 'academy', 'accenture', 'accountant', 'accountants', 'active', 'actor', 'ad', 'ads', 'adult', 'ae', 'aero', 'af', 'afl', 'ag', 'agency', 'ai', 'aig', 'airforce', 'al', 'allfinanz', 'alsace', 'am', 'amsterdam', 'an', 'android', 'ao', 'apartments', 'aq', 'aquarelle', 'ar', 'archi', 'army', 'arpa', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'auction', 'audio', 'auto', 'autos', 'aw', 'ax', 'axa', 'az', 'azure', 'ba', 'band', 'bank', 'bar', 'barclaycard', 'barclays', 'bargains', 'bauhaus', 'bayern', 'bb', 'bbc', 'bbva', 'bd', 'be', 'beer', 'berlin', 'best', 'bf', 'bg', 'bh', 'bi', 'bible', 'bid', 'bike', 'bingo', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'bloomberg', 'blue', 'bm', 'bmw', 'bn', 'bnpparibas', 'bo', 'boats', 'bond', 'boo', 'boutique', 'br', 'bridgestone', 'broker', 'brother', 'brussels', 'bs', 'bt', 'budapest', 'build', 'builders', 'business', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'cafe', 'cal', 'camera', 'camp', 'cancerresearch', 'canon', 'capetown', 'capital', 'caravan', 'cards', 'care', 'career', 'careers', 'cars', 'cartier', 'casa', 'cash', 'casino', 'cat', 'catering', 'cbn', 'cc', 'cd', 'center', 'ceo', 'cern', 'cf', 'cfa', 'cfd', 'cg', 'ch', 'channel', 'chat', 'cheap', 'chloe', 'christmas', 'chrome', 'church', 'ci', 'cisco', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'click', 'clinic', 'clothing', 'club', 'cm', 'cn', 'co', 'coach', 'codes', 'coffee', 'college', 'cologne', 'com', 'community', 'company', 'computer', 'condos', 'construction', 'consulting', 'contractors', 'cooking', 'cool', 'coop', 'corsica', 'country', 'coupons', 'courses', 'cr', 'credit', 'creditcard', 'cricket', 'crs', 'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dabur', 'dad', 'dance', 'date', 'dating', 'datsun', 'day', 'dclk', 'de', 'deals', 'degree', 'delivery', 'democrat', 'dental', 'dentist', 'desi', 'design', 'dev', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'dog', 'doha', 'domains', 'doosan', 'download', 'durban', 'dvag', 'dz', 'earth', 'eat', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'epson', 'equipment', 'er', 'erni', 'es', 'esq', 'estate', 'et', 'eu', 'eurovision', 'eus', 'events', 'everbank', 'exchange', 'expert', 'exposed', 'express', 'fail', 'faith', 'fan', 'fans', 'farm', 'fashion', 'feedback', 'fi', 'film', 'finance', 'financial', 'firmdale', 'fish', 'fishing', 'fit', 'fitness', 'fj', 'fk', 'flights', 'florist', 'flowers', 'flsmidth', 'fly', 'fm', 'fo', 'foo', 'football', 'forex', 'forsale', 'foundation', 'fr', 'frl', 'frogans', 'fund', 'furniture', 'futbol', 'fyi', 'ga', 'gal', 'gallery', 'garden', 'gb', 'gbiz', 'gd', 'gdn', 'ge', 'gent', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift', 'gifts', 'gives', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmo', 'gmx', 'gn', 'gold', 'goldpoint', 'golf', 'goo', 'goog', 'google', 'gop', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gratis', 'green', 'gripe', 'gs', 'gt', 'gu', 'guge', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hamburg', 'hangout', 'haus', 'healthcare', 'help', 'here', 'hermes', 'hiphop', 'hitachi', 'hiv', 'hk', 'hm', 'hn', 'hockey', 'holdings', 'holiday', 'homedepot', 'homes', 'honda', 'horse', 'host', 'hosting', 'house', 'how', 'hr', 'ht', 'hu', 'ibm', 'icbc', 'icu', 'id', 'ie', 'ifm', 'il', 'im', 'immo', 'immobilien', 'in', 'industries', 'infiniti', 'info', 'ing', 'ink', 'institute', 'insure', 'int', 'international', 'investments', 'io', 'iq', 'ir', 'irish', 'is', 'it', 'iwc', 'java', 'jcb', 'je', 'jetzt', 'jewelry', 'jll', 'jm', 'jo', 'jobs', 'joburg', 'jp', 'juegos', 'kaufen', 'kddi', 'ke', 'kg', 'kh', 'ki', 'kim', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'komatsu', 'kp', 'kr', 'krd', 'kred', 'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'land', 'lat', 'latrobe', 'lawyer', 'lb', 'lc', 'lds', 'lease', 'leclerc', 'legal', 'lgbt', 'li', 'liaison', 'lidl', 'life', 'lighting', 'limited', 'limo', 'link', 'lk', 'loan', 'loans', 'lol', 'london', 'lotte', 'lotto', 'love', 'lr', 'ls', 'lt', 'ltda', 'lu', 'lupin', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid', 'maif', 'maison', 'management', 'mango', 'market', 'marketing', 'markets', 'marriott', 'mba', 'mc', 'md', 'me', 'media', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu', 'mg', 'mh', 'miami', 'mil', 'mini', 'mk', 'ml', 'mm', 'mma', 'mn', 'mo', 'mobi', 'moda', 'moe', 'monash', 'money', 'montblanc', 'mormon', 'mortgage', 'moscow', 'motorcycles', 'mov', 'movie', 'mp', 'mq', 'mr', 'ms', 'mt', 'mtn', 'mtpc', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nadex', 'nagoya', 'name', 'navy', 'nc', 'ne', 'nec', 'net', 'network', 'neustar', 'new', 'news', 'nexus', 'nf', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'ninja', 'nissan', 'nl', 'no', 'np', 'nr', 'nra', 'nrw', 'ntt', 'nu', 'nyc', 'nz', 'okinawa', 'om', 'one', 'ong', 'onl', 'online', 'ooo', 'oracle', 'org', 'organic', 'osaka', 'otsuka', 'ovh', 'pa', 'page', 'panerai', 'paris', 'partners', 'parts', 'party', 'pe', 'pf', 'pg', 'ph', 'pharmacy', 'philips', 'photo', 'photography', 'photos', 'physio', 'piaget', 'pics', 'pictet', 'pictures', 'pink', 'pizza', 'pk', 'pl', 'place', 'plumbing', 'plus', 'pm', 'pn', 'pohl', 'poker', 'porn', 'post', 'pr', 'praxi', 'press', 'pro', 'prod', 'productions', 'prof', 'properties', 'property', 'ps', 'pt', 'pub', 'pw', 'py', 'qa', 'qpon', 'quebec', 'racing', 're', 'realtor', 'recipes', 'red', 'redstone', 'rehab', 'reise', 'reisen', 'reit', 'ren', 'rent', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review', 'reviews', 'rich', 'rio', 'rip', 'ro', 'rocks', 'rodeo', 'rs', 'rsvp', 'ru', 'ruhr', 'run', 'rw', 'ryukyu', 'sa', 'saarland', 'sale', 'samsung', 'sandvik', 'sandvikcoromant', 'sap', 'sarl', 'saxo', 'sb', 'sc', 'sca', 'scb', 'schmidt', 'scholarships', 'school', 'schule', 'schwarz', 'science', 'scot', 'sd', 'se', 'seat', 'sener', 'services', 'sew', 'sex', 'sexy', 'sg', 'sh', 'shiksha', 'shoes', 'show', 'shriram', 'si', 'singles', 'site', 'sj', 'sk', 'ski', 'sky', 'sl', 'sm', 'sn', 'sncf', 'so', 'soccer', 'social', 'software', 'sohu', 'solar', 'solutions', 'sony', 'soy', 'space', 'spiegel', 'spreadbetting', 'sr', 'st', 'study', 'style', 'su', 'sucks', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'swiss', 'sx', 'sy', 'sydney', 'systems', 'sz', 'taipei', 'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'td', 'team', 'tech', 'technology', 'tel', 'temasek', 'tennis', 'tf', 'tg', 'th', 'thd', 'theater', 'tickets', 'tienda', 'tips', 'tires', 'tirol', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'top', 'toray', 'toshiba', 'tours', 'town', 'toys', 'tr', 'trade', 'trading', 'training', 'travel', 'trust', 'tt', 'tui', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'university', 'uno', 'uol', 'us', 'uy', 'uz', 'va', 'vacations', 'vc', 've', 'vegas', 'ventures', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video', 'villas', 'vision', 'vlaanderen', 'vn', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'vu', 'wales', 'walter', 'wang', 'watch', 'webcam', 'website', 'wed', 'wedding', 'weir', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'win', 'wme', 'work', 'works', 'world', 'ws', 'wtc', 'wtf', 'xbox', 'xerox', 'xin', 'xn--1qqw23a', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c', 'xn--45q11c', 'xn--4gbrim', 'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--90ais', 'xn--9et52u', 'xn--b4w605ferd', 'xn--c1avg', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t', 'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--estv75g', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--gecrj9c', 'xn--h2brj9c', 'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1amh', 'xn--j6w193g', 'xn--kcrx77d1x4a', 'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd', 'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar', 'xn--mgbpl2fh', 'xn--mgbx4cd0ab', 'xn--mxtq1m', 'xn--ngbc5azd', 'xn--node', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--p1acf', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--qcka1pmc', 'xn--rhqv96g', 'xn--s9brj9c', 'xn--ses554g', 'xn--unup4y', 'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--vuq861b', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yandex', 'ye', 'yodobashi', 'yoga', 'yokohama', 'youtube', 'yt', 'za', 'zip', 'zm', 'zone', 'zuerich', 'zw']
ip_regex = r'([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})'
hostname_regex = r"((([\w\-]+\.)*)([\w\-]+))\.?"
email_regex = r"([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?"
hash_regex = r"([a-fA-F0-9]{32,64})"
url_regex = r"""
            (
              ((?P<scheme>[\w]{2,9}):\/\/)?
              ([\S]*\:[\S]*\@)?
              (?P<hostname>(
                          ((([\w\-]+\.)+)
                          ([a-zA-Z]{2,6}))
                          |([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})
                          |([\w\-]+)
                          )
              )
              (\:[\d]{1,5})?
              (?P<path>(\/[\S]*)?
                (\?[\S]*)?
                (\#[\S]*)?)
            )
        """


def is_url(url):
    match = re.match("^" + url_regex + "$", url, re.VERBOSE)
    if match:
        url = match.group(1)
        if url.find('/') != -1:
            return match.group(1)
    else:
        return None


def is_ip(ip):
    if ip:
        match = re.match("^" + ip_regex + "$", ip)
        if match:
            return match.group(1)
    else:
        return False


def is_hostname(hostname):
    hostname = hostname.lower()
    if hostname:
        match = re.match("^" + hostname_regex + "$", hostname)
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        tld = hostname.split('.')[-1:][0]
        if match and (tld in tlds):
            return match.group(1)
    else:
        return False


def is_subdomain(hostname):
    if hostname:
        hostname = is_hostname(hostname)
        if hostname:
            tld = hostname.split('.')[-1:][0]
            if tld in tlds:
                tld = hostname.split('.')[-2:][0]
                if tld in tlds:
                    domain = ".".join(hostname.split('.')[-3:])
                    if domain == hostname:
                        return False
                    else:
                        return domain
                else:
                    domain = ".".join(hostname.split('.')[-2:])
                    if domain == hostname:
                        return False
                    else:
                        return domain
    else:
        return False
