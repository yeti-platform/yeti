"""Certificate and CertificateSubject observables are used to handle
X509 certificates that can be used in SSL/TLS connections, or for
S/MIME encrypted or signed e-mails.

"""

import hashlib
from io import BytesIO

from mongoengine.fields import DictField, ListField, ReferenceField, StringField

from core.database import AttachedFile
from core.observables import Observable


class Certificate(Observable):
    """X509 certificate"""

    value = StringField(verbose_name="Value")
    hashes = ListField(DictField(), verbose_name="Hashes")
    body = ReferenceField("AttachedFile")

    exclude_fields = Observable.exclude_fields + ["body"]

    @staticmethod
    def check_type(txt):
        return True

    @classmethod
    def from_data(cls, data, hash_sha256=None):
        """Creates a Certificate observable based on raw certificate data and
        its hash_sha256 value.

        """
        if hash_sha256 is None:
            hash_sha256 = hashlib.sha256(data).hexdigest()
        body = AttachedFile.from_content(
            BytesIO(data),
            "cert.der",
            "application/pkix-cert",
        )
        return cls.get_or_create(
            value="CERT:{}".format(hash_sha256),
            body=body,
        )


class CertificateSubject(Observable):
    """X509 certificate subject. Can be linked to X509 certificates based
    on their subject and issuer fields.

    """

    value = StringField(verbose_name="Text subject")

    @staticmethod
    def check_type(txt):
        return True
