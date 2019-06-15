import logging

from core.errors import ObservableValidationError
from core.observables import Certificate

def register_certificate(content, context, source):
    """Helper function to register certificate

    Args:
        content (str): is content
        context (dict): observable context
        source (str): origin of observable
    """

    try:
        cert_data = Certificate.from_data(content)
        cert_data.add_context(context)
        cert_data.add_source(source)
    except ObservableValidationError as e:
        logging.error(e)

def register_observables(mapper, observables, blacklist_domains, context, source):
    """Helper function to register data obteined by from_text

    Args:
        mapped (dict): observable mapping dictionary
            e.g. {'MacAddress': MacAddress}
        observables (dict): obteined by func from_text
        blacklist_domains (list): list of domains to ignore in urls
        context (dict): observable context
        source (str): origin of observable
    """

    for key in observables:
        for ioc in filter(None, observables[key]):
            if key == 'Url' and any(
                    [domain in ioc for domain in blacklist_domains]):
                continue
            try:
                ioc_data = mapper[key].get_or_create(value=ioc)
                ioc_data.add_context(context)
                ioc_data.add_source(source)
            except ObservableValidationError as e:
                logging.error(e)
            except UnicodeDecodeError as e:
                logging.error(e)
