import datetime
import hashlib
import io
import pathlib
import time
import unittest

from core import database_arango
from core.schemas import observable
from core.schemas.graph import Relationship
from core.schemas.observable import Observable
from core.schemas.observables import (
    asn,
    auth_secret,
    bic,
    certificate,
    cidr,
    command_line,
    container_image,
    email,
    file,
    generic,
    hostname,
    iban,
    imphash,
    ipv4,
    ipv6,
    ja3,
    mac_address,
    md5,
    mutex,
    named_pipe,
    path,
    registry_key,
    sha1,
    sha256,
    ssdeep,
    tlsh,
    url,
    user_account,
    user_agent,
    wallet,
)


class ObservableTest(unittest.TestCase):
    OBSERVABLE_TEST_DATA_CASES = [
        ("1.1.1.1", ipv4.IPv4),
        ("8.8.8.8", ipv4.IPv4),
        ("tomchop.me", hostname.Hostname),
        ("google.com", hostname.Hostname),
        ("http://google.com/", url.Url),
        ("http://tomchop.me/", url.Url),
        ("d41d8cd98f00b204e9800998ecf8427e", md5.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1.SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha256.SHA256,
        ),
        ("tom_chop.me", hostname.Hostname),
    ]

    OBSERVABLE_TEST_DATA_FILE = "tests/observable_test_data/iocs.txt"

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.db = database_arango.db

    def test_observable_create(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        self.assertIsNotNone(result.id)
        self.assertEqual(result.value, "toto.com")

    def test_observable_update(self) -> None:
        """Tests that calling save() on an observable treats it as PATCH."""
        result = registry_key.RegistryKey(
            key="Microsoft\\Windows\\CurrentVersion\\Run",
            value="persist",
            data=b"cmd.exe",
            hive=registry_key.RegistryHive.HKEY_LOCAL_MACHINE_Software,
        ).save()
        result.tag(["tag1"])
        result.add_context(source="source1", context={"some": "info"})
        self.assertEqual([tag.name for tag in result.tags], ["tag1"])
        self.assertEqual(result.context[0], {"source": "source1", "some": "info"})
        result = registry_key.RegistryKey(
            key="Microsoft\\Windows\\CurrentVersion\\RunOnce",
            value="persist",
            data=b"other.exe",
            hive=registry_key.RegistryHive.HKEY_LOCAL_MACHINE_Software,
        ).save()
        self.assertEqual(result.key, "Microsoft\\Windows\\CurrentVersion\\RunOnce")
        self.assertEqual(result.data, b"other.exe")
        self.assertEqual([tag.name for tag in result.tags], ["tag1"])
        self.assertEqual(result.context[0], {"source": "source1", "some": "info"})

    def test_create_generic_observable(self):
        result = generic.Generic(value="Some_String").save()
        self.assertIsNotNone(result.id)
        self.assertEqual(result.value, "Some_String")
        self.assertEqual(result.type, "generic")

    def test_observable_no_value(self):
        with self.assertRaises(ValueError):
            hostname.Hostname(value="").save()

    def test_observable_same_value_different_types(self):
        """Tests that two observables with the same value but different types
        are not the same observable."""
        obs1 = user_account.UserAccount(value="test@test.com").save()
        obs2 = email.Email(value="test@test.com").save()
        self.assertNotEqual(obs1.id, obs2.id)

    def test_two_observables_same_value_same_type(self):
        """Tests that two observables with the same value and same type
        are the same observable."""
        obs1 = user_account.UserAccount(value="test@test.com").save()
        obs2 = user_account.UserAccount(value="test@test.com").save()
        self.assertEqual(obs1.id, obs2.id)

    def test_observable_find(self) -> None:
        hostname.Hostname(value="toto.com").save()
        observable_obj = observable.find(value="toto.com")
        self.assertIsNotNone(observable_obj)
        assert observable_obj is not None
        self.assertEqual(observable_obj.value, "toto.com")  #

        observable_obj = Observable.find(value="tata.com")
        self.assertIsNone(observable_obj)

    def test_observable_get(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        assert result.id is not None
        observable_obj = Observable.get(result.id)
        assert observable_obj is not None
        self.assertIsNotNone(observable_obj)
        self.assertEqual(observable_obj.value, "toto.com")

    def test_observable_filter(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        obs2 = hostname.Hostname(value="test2.com").save()
        time.sleep(1)

        result, total = Observable.filter(query_args={"value": "test"})
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        actual = [r.value for r in result]
        self.assertIn("test1.com", actual)
        self.assertIn("test2.com", actual)
        actual = [r.id for r in result]
        self.assertIn(obs1.id, actual)
        self.assertIn(obs2.id, actual)

    def test_observable_filter_in(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        hostname.Hostname(value="test2.com").save()
        obs2 = hostname.Hostname(value="test3.com").save()
        time.sleep(1)

        result, total = Observable.filter(
            query_args={"value__in": ["test1.com", "test3.com"]}
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        actual = [r.value for r in result]
        self.assertIn("test1.com", actual)
        self.assertIn("test3.com", actual)
        actual = [r.id for r in result]
        self.assertIn(obs1.id, actual)
        self.assertIn(obs2.id, actual)

    def test_observable_link_to(self) -> None:
        observable1 = hostname.Hostname(value="toto.com").save()
        observable2 = hostname.Hostname(value="tata.com").save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc1")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)

    def test_observable_update_link(self) -> None:
        observable1 = hostname.Hostname(value="toto.com").save()
        observable2 = hostname.Hostname(value="tata.com").save()

        relationship = observable1.link_to(observable2, "test_reltype", "desc1")
        relationship = observable1.link_to(observable2, "test_reltype", "desc2")
        self.assertEqual(relationship.type, "test_reltype")
        self.assertEqual(relationship.description, "desc2")
        all_relationships = list(Relationship.list())
        self.assertEqual(len(all_relationships), 1)
        self.assertEqual(all_relationships[0].description, "desc2")

    def test_observable_neighbor(self) -> None:
        observable1 = hostname.Hostname(value="tomchop.me").save()
        observable2 = ipv4.IPv4(value="127.0.0.1").save()

        relationship = observable1.link_to(observable2, "resolves", "DNS resolution")
        self.assertEqual(relationship.type, "resolves")

        vertices, paths, count = observable1.neighbors()

        self.assertEqual(len(paths), 1)
        self.assertEqual(count, 1)
        self.assertEqual(len(vertices), 1)

        self.assertEqual(paths[0][0].source, observable1.extended_id)
        self.assertEqual(paths[0][0].target, observable2.extended_id)
        self.assertEqual(paths[0][0].description, "DNS resolution")
        self.assertEqual(paths[0][0].type, "resolves")

        self.assertIn(observable2.extended_id, vertices)
        neighbor = vertices[observable2.extended_id]
        self.assertEqual(neighbor.id, observable2.id)

    def test_add_context(self) -> None:
        """Tests that one or more contexts is added and persisted in the DB."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source2", {"abc": 123, "def": 456})

        assert observable_obj.id is not None
        observable_obj = Observable.get(observable_obj.id)
        self.assertEqual(len(observable_obj.context), 2)
        self.assertEqual(observable_obj.context[0]["abc"], 123)
        self.assertEqual(observable_obj.context[0]["source"], "test_source")
        self.assertEqual(observable_obj.context[1]["abc"], 123)
        self.assertEqual(observable_obj.context[1]["source"], "test_source2")

    def test_add_dupe_context(self) -> None:
        """Tests that identical contexts aren't added twice."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        self.assertEqual(len(observable_obj.context), 1)

    def test_add_new_context_with_same_source(self) -> None:
        """Tests that diff contexts with same source are added separately."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source", {"abc": 123, "def": 666})
        self.assertEqual(len(observable_obj.context), 2)

    def test_add_multiple_contexts_with_same_source(self) -> None:
        """Tests that two different contexts can be added from the same source."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source", {"abc": 123, "def": 666})
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source", {"abc": 123, "def": 666})
        self.assertEqual(len(observable_obj.context), 2)
        self.assertEqual(
            observable_obj.context[0], {"source": "test_source", "abc": 123, "def": 456}
        )
        self.assertEqual(
            observable_obj.context[1], {"source": "test_source", "abc": 123, "def": 666}
        )

    def test_add_new_context_with_same_source_and_ignore_field(self) -> None:
        """Tests that the context is updated if the difference is not being
        compared."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context("test_source", {"abc": 999, "def": 456})
        observable_obj.add_context(
            "test_source", {"abc": 123, "def": 666}, skip_compare={"def"}
        )
        self.assertEqual(len(observable_obj.context), 2)
        self.assertEqual(observable_obj.context[0]["def"], 666)
        self.assertEqual(observable_obj.context[1]["abc"], 999)

    def test_overwrite_context(self) -> None:
        """Tests that one or more contexts is added and persisted in the DB."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj.add_context("test_source", {"abc": 123, "def": 456})
        observable_obj.add_context(
            "test_source", {"abc": 456, "def": 123}, overwrite=True
        )

        assert observable_obj.id is not None
        observable_obj = Observable.get(observable_obj.id)
        self.assertEqual(len(observable_obj.context), 1)
        self.assertEqual(observable_obj.context[0]["abc"], 456)
        self.assertEqual(observable_obj.context[0]["def"], 123)
        self.assertEqual(observable_obj.context[0]["source"], "test_source")

    def test_delete_context(self) -> None:
        """Tests that a context is deleted if contents fully match."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj = observable_obj.add_context(
            "test_source", {"abc": 123, "def": 456}
        )
        observable_obj = observable_obj.delete_context(
            "test_source", {"def": 456, "abc": 123}
        )
        assert observable_obj.id is not None
        observable_obj = observable_obj.get(observable_obj.id)  # type: ignore

        self.assertEqual(len(observable_obj.context), 0)

    def test_delete_context_diff(self) -> None:
        """Tests that a context is not deleted if contents don't match."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj = observable_obj.add_context(
            "test_source", {"abc": 123, "def": 456}
        )
        observable_obj = observable_obj.delete_context(
            "test_source", {"def": 456, "abc": 000}
        )
        observable_obj = observable_obj.get(observable_obj.id)  # type: ignore
        self.assertEqual(len(observable_obj.context), 1)

    def tests_delete_context_skip_compare(self) -> None:
        """Tests that a context is deleted if the difference is not being
        compared."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        observable_obj = observable_obj.add_context(
            "test_source", {"abc": 123, "def": 456}
        )
        observable_obj = observable_obj.delete_context(
            "test_source", {"abc": 000, "def": 456}, skip_compare={"abc"}
        )
        observable_obj = Observable.get(observable_obj.id)  # type: ignore
        self.assertEqual(len(observable_obj.context), 0)

    def test_duplicate_value(self) -> None:
        """Tests saving two observables with the same value return the same observable."""
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop.me").save()
        self.assertEqual(obs1.id, obs2.id)

    def test_create_asn(self) -> None:
        """Tests creating an ASN."""
        observable_obj = asn.ASN(value="AS123").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "AS123")
        self.assertIsInstance(observable_obj, asn.ASN)

    def test_create_auth_secret(self) -> None:
        """Tests creating an AuthSecret."""
        pub_key = """MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE="""
        observable_obj = auth_secret.AuthSecret(
            value=pub_key, auth_type="pubkey"
        ).save()
        self.assertIsInstance(observable_obj, auth_secret.AuthSecret)
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, pub_key)
        self.assertEqual(observable_obj.auth_type, "pubkey")

    def test_create_wallet(self) -> None:
        """Tests creating a wallet."""
        observable_obj = wallet.Wallet(
            value="btc/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            coin="btc",
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ).save()
        self.assertIsInstance(observable_obj, wallet.Wallet)
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "btc/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertEqual(observable_obj.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertEqual(observable_obj.coin, "btc")

    def test_create_certificate(self) -> None:
        """Tests creating a certificate."""
        observable_obj = certificate.Certificate.from_data(b"1234").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(
            observable_obj.value,
            "CERT:03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
        )
        self.assertIsInstance(observable_obj, certificate.Certificate)

    def test_create_cidr(self) -> None:
        """Tests creating a CIDR."""
        observable_obj = cidr.CIDR(value="0.0.0.0/0").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "0.0.0.0/0")
        self.assertIsInstance(observable_obj, cidr.CIDR)

    def test_create_command_line(self) -> None:
        """Tests creating a command line."""
        observable_obj = command_line.CommandLine(value="ls -la").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "ls -la")
        self.assertIsInstance(observable_obj, command_line.CommandLine)

    def test_create_docker_image(self) -> None:
        """Tests creating a docker image."""
        observable_obj = container_image.DockerImage(
            value="yetiplatform/yeti:latest"
        ).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "yetiplatform/yeti:latest")
        self.assertIsInstance(observable_obj, container_image.DockerImage)

    def test_create_email(self) -> None:
        """Tests creating an email."""
        observable_obj = email.Email(value="example@gmail.com").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "example@gmail.com")
        self.assertIsInstance(observable_obj, email.Email)

    def test_create_file(self) -> None:
        """Tests creating a file."""
        observable_obj = file.File(value="FILE:HASH").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "FILE:HASH")
        self.assertIsInstance(observable_obj, file.File)

    def test_create_hostname(self) -> None:
        """Tests creating a hostname."""
        observable_obj = hostname.Hostname(value="tomchop.me").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "tomchop.me")
        self.assertIsInstance(observable_obj, hostname.Hostname)

    def test_create_hostname_with_underscore(self) -> None:
        """Tests creating a hostname."""
        observable_obj = hostname.Hostname(value="tom_chop.me").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "tom_chop.me")
        self.assertIsInstance(observable_obj, hostname.Hostname)

    def test_create_imphash(self) -> None:
        """Tests creating an imphash."""
        observable_obj = imphash.Imphash(value="1234567890").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1234567890")
        self.assertIsInstance(observable_obj, imphash.Imphash)

    def test_create_mutex(self) -> None:
        """Tests creating a mutex."""
        mutex_obs = mutex.Mutex(value="test_mutex").save()
        self.assertIsNotNone(mutex_obs.id)
        self.assertEqual(mutex_obs.value, "test_mutex")

    def test_create_named_pipe(self) -> None:
        """Tests creating a name pipe."""
        observable_obj = named_pipe.NamedPipe(value="\\\\.\\pipe\\test").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "\\\\.\\pipe\\test")

    def test_create_ipv4(self) -> None:
        """Tests creating an IPv4."""
        observable_obj = ipv4.IPv4(value="127.0.0.1").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "127.0.0.1")
        self.assertIsInstance(observable_obj, ipv4.IPv4)

    def test_create_ipv6(self) -> None:
        """Tests creating an IPv6."""
        observable_obj = ipv6.IPv6(value="::1").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "::1")
        self.assertIsInstance(observable_obj, ipv6.IPv6)

    def test_create_ja3(self) -> None:
        """Tests creating a JA3."""
        observable_obj = ja3.JA3(value="1234567890").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1234567890")
        self.assertEqual(observable_obj.type, "ja3")

    def test_create_mac_address(self) -> None:
        """Tests creating a MAC address."""
        observable_obj = mac_address.MacAddress(value="00:00:00:00:00:00").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "00:00:00:00:00:00")
        self.assertIsInstance(observable_obj, mac_address.MacAddress)

    def test_create_iban(self) -> None:
        """Tests creating an IBAN."""
        observable_obj = iban.IBAN(value="GB33BUKB20201555555555").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "GB33BUKB20201555555555")
        self.assertIsInstance(observable_obj, iban.IBAN)

    def test_create_bic(self) -> None:
        """Tests creating a BIC."""
        observable_obj = bic.BIC(value="BUKBGB22XXX").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "BUKBGB22XXX")
        self.assertIsInstance(observable_obj, bic.BIC)

    def test_create_md5(self) -> None:
        """Tests creating an MD5."""
        md5_hash = hashlib.md5(b"1234567890").hexdigest()
        observable_obj = md5.MD5(value=md5_hash).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, md5_hash)
        self.assertIsInstance(observable_obj, md5.MD5)

    def test_create_path(self) -> None:
        """Tests creating a path."""
        observable_obj = path.Path(value="/var/test").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "/var/test")
        self.assertIsInstance(observable_obj, path.Path)

    def test_create_registry_key(self) -> None:
        """Tests creating a registry key."""
        observable_obj = registry_key.RegistryKey(
            key="Microsoft\\Windows\\CurrentVersion\\Run",
            value="persist",
            data=b"cmd.exe",
            hive=registry_key.RegistryHive.HKEY_LOCAL_MACHINE_Software,
        ).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "persist")
        self.assertIsInstance(observable_obj, registry_key.RegistryKey)

    def test_create_sha1(self) -> None:
        """Tests creating a SHA1."""
        sha1_hash = hashlib.sha1(b"1234567890").hexdigest()
        observable_obj = sha1.SHA1(value=sha1_hash).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, sha1_hash)
        self.assertIsInstance(observable_obj, sha1.SHA1)

    def test_create_sha256(self) -> None:
        """Tests creating a SHA256."""
        sha256_hash = hashlib.sha256(b"1234567890").hexdigest()
        observable_obj = sha256.SHA256(value=sha256_hash).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, sha256_hash)
        self.assertIsInstance(observable_obj, sha256.SHA256)

    def test_create_ssdeep(self) -> None:
        """Tests creating an ssdeep."""
        observable_obj = ssdeep.Ssdeep(value="1234567890").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1234567890")
        self.assertIsInstance(observable_obj, ssdeep.Ssdeep)

    def test_create_tlsh(self) -> None:
        """Tests creating a TLSH."""
        observable_obj = tlsh.TLSH(value="1234567890").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1234567890")
        self.assertIsInstance(observable_obj, tlsh.TLSH)

    def test_create_url(self) -> None:
        """Tests creating a URL."""
        observable_obj = url.Url(value="https://www.google.com").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "https://www.google.com")
        self.assertIsInstance(observable_obj, url.Url)

    def test_create_url_with_underscore(self) -> None:
        """Tests creating a URL."""
        observable_obj = url.Url(value="https://www.goo_gle.com").save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "https://www.goo_gle.com")
        self.assertIsInstance(observable_obj, url.Url)

    def test_create_user_agent(self) -> None:
        """Tests creating a user agent."""
        observable_obj = user_agent.UserAgent(
            value="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ).save()  # noqa: E501
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(
            observable_obj.value,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        )  # noqa: E501
        self.assertIsInstance(observable_obj, user_agent.UserAgent)

    def test_create_user_account(self) -> None:
        """Tests creating a user account."""
        observable_obj = user_account.UserAccount(
            value="test_account",
            user_id="test_user_id",
            credential="test_credential",
            account_login="test_account_login",
            account_type="test_account_type",
            display_name="test_display_name",
            is_service_account=True,
            is_privileged=True,
            can_escalate_privs=True,
            is_disabled=True,
            account_created=datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
            account_expires=datetime.datetime(
                2023, 12, 31, tzinfo=datetime.timezone.utc
            ),
            credential_last_changed=datetime.datetime(
                2023, 1, 1, tzinfo=datetime.timezone.utc
            ),
            account_first_login=datetime.datetime(
                2023, 1, 1, tzinfo=datetime.timezone.utc
            ),
            account_last_login=datetime.datetime(
                2023, 12, 15, tzinfo=datetime.timezone.utc
            ),
        ).save()
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "test_account")
        self.assertIsInstance(observable_obj, user_account.UserAccount)
        self.assertEqual(observable_obj.user_id, "test_user_id")
        self.assertEqual(observable_obj.credential, "test_credential")
        self.assertEqual(observable_obj.account_login, "test_account_login")
        self.assertEqual(observable_obj.account_type, "test_account_type")
        self.assertEqual(observable_obj.display_name, "test_display_name")
        self.assertEqual(observable_obj.is_service_account, True)
        self.assertEqual(observable_obj.is_privileged, True)
        self.assertEqual(observable_obj.can_escalate_privs, True)
        self.assertEqual(observable_obj.is_disabled, True)
        self.assertEqual(
            observable_obj.account_created,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable_obj.account_expires,
            datetime.datetime(2023, 12, 31, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable_obj.credential_last_changed,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable_obj.account_first_login,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable_obj.account_last_login,
            datetime.datetime(2023, 12, 15, tzinfo=datetime.timezone.utc),
        )

    def test_create_user_account_incoherent_dates(self) -> None:
        """Tests creating a user account with incoherent dates."""
        with self.assertRaises(ValueError):
            user_account.UserAccount(
                value="test_account",
                account_created=datetime.datetime(
                    2023, 12, 31, tzinfo=datetime.timezone.utc
                ),
                account_expires=datetime.datetime(
                    2023, 1, 1, tzinfo=datetime.timezone.utc
                ),
            ).save()

    def test_create_observable_with_type(self) -> None:
        """Tests creating an observable."""
        observable_obj = observable.create(value="1.1.1[.]1", type="ipv4")
        self.assertNotIn("id", observable_obj)
        self.assertEqual(observable_obj.value, "1.1.1.1")
        self.assertIsInstance(observable_obj, ipv4.IPv4)

    def test_create_obsersable_without_type(self) -> None:
        """Tests creating an observable without specifying a type."""
        observable_obj = observable.create(value="1.1.1[.]1")
        self.assertNotIn("id", observable_obj)
        self.assertEqual(observable_obj.value, "1.1.1.1")
        self.assertIsInstance(observable_obj, ipv4.IPv4)

    def test_save_observable_with_type(self) -> None:
        """Tests saving an observable."""
        observable_obj = observable.save(value="1.1.1[.]1", type="ipv4")
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1.1.1.1")
        observable_obj = Observable.find(value="1.1.1.1")
        self.assertIsNotNone(observable_obj)
        self.assertIsInstance(observable_obj, ipv4.IPv4)
        self.assertEqual(observable_obj.value, "1.1.1.1")

    def test_save_observable_without_type(self) -> None:
        """Tests saving an observable without specifying a type."""
        observable_obj = observable.save(value="1.1.1[.]1")
        self.assertIsNotNone(observable_obj.id)
        self.assertEqual(observable_obj.value, "1.1.1.1")
        observable_obj = Observable.find(value="1.1.1.1")
        self.assertIsNotNone(observable_obj)
        self.assertIsInstance(observable_obj, ipv4.IPv4)
        self.assertEqual(observable_obj.value, "1.1.1.1")

    def test_find_observable(self) -> None:
        """Tests finding an observable."""
        observable.save(value="1.1.1[.]1")
        observable_obj = observable.find(value="1.1.1.1")
        self.assertIsNotNone(observable_obj)
        self.assertIsInstance(observable_obj, ipv4.IPv4)
        self.assertEqual(observable_obj.value, "1.1.1.1")

    def test_create_observables_from_text(self) -> None:
        with open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r") as f:
            text = f.read()
        observables, unknown = observable.create_from_text(text)
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 0)
        self.assertEqual(unknown[0], "junk")

    def test_save_observables_from_text(self) -> None:
        """Tests saving observables from text."""
        with open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r") as f:
            text = f.read()
        observables, unknown = observable.save_from_text(text, tags=["tag1", "tag2"])
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNotNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 2)
            self.assertEqual(observables[i].tags[0].fresh, True)
            self.assertEqual(observables[i].tags[1].fresh, True)
        self.assertEqual(unknown[0], "junk")

    def test_create_observables_from_str_file_path(self) -> None:
        """Tests creating observables string from file path."""
        filepath = ObservableTest.OBSERVABLE_TEST_DATA_FILE
        observables, unknown = observable.create_from_file(file=filepath)
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 0)
        self.assertEqual(unknown[0], "junk")

    def save_observables_from_str_file_path(self) -> None:
        """Tests saving observables from string file path."""
        filepath = ObservableTest.OBSERVABLE_TEST_DATA_FILE
        observables, unknown = observable.save_from_file(
            filepath, tags=["tag1", "tag2"]
        )
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNotNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 2)
            self.assertEqual(observables[i].tags[0].fresh, True)
            self.assertEqual(observables[i].tags[1].fresh, True)
        self.assertEqual(unknown[0], "junk")

    def test_create_observables_from_pathlib(self) -> None:
        path = pathlib.Path(ObservableTest.OBSERVABLE_TEST_DATA_FILE)
        observables, unknown = observable.create_from_file(path)
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 0)
        self.assertEqual(unknown[0], "junk")

    def test_save_observables_from_pathlib(self) -> None:
        path = pathlib.Path(ObservableTest.OBSERVABLE_TEST_DATA_FILE)
        observables, unknown = observable.save_from_file(path, tags=["tag1", "tag2"])
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNotNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 2)
            self.assertEqual(observables[i].tags[0].fresh, True)
            self.assertEqual(observables[i].tags[1].fresh, True)
        self.assertEqual(unknown[0], "junk")

    def test_create_observable_from_file_object(self) -> None:
        file = open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r")
        observables, unknown = observable.create_from_file(file)
        file.close()
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 0)
        self.assertEqual(unknown[0], "junk")

    def save_observables_from_file_object(self) -> None:
        file = open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r")
        observables, unknown = observable.save_from_file(file, tags=["tag1", "tag2"])
        file.close()
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNotNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 2)
            self.assertEqual(observables[i].tags[0].fresh, True)
            self.assertEqual(observables[i].tags[1].fresh, True)
        self.assertEqual(unknown[0], "junk")

    def test_create_observables_from_string_io(self) -> None:
        with open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r") as f:
            file_io = io.StringIO(f.read())
        observables, unknown = observable.create_from_file(file_io)
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 0)
        self.assertEqual(unknown[0], "junk")

    def test_save_observables_from_string_io(self) -> None:
        with open(ObservableTest.OBSERVABLE_TEST_DATA_FILE, "r") as f:
            file_io = io.StringIO(f.read())
        observables, unknown = observable.save_from_file(file_io, tags=["tag1", "tag2"])
        self.assertEqual(len(observables), 10)
        self.assertEqual(len(unknown), 1)
        for i, (expected_value, expected_class) in enumerate(
            ObservableTest.OBSERVABLE_TEST_DATA_CASES
        ):
            self.assertIsInstance(observables[i], expected_class)
            self.assertIsNotNone(observables[i].id)
            self.assertEqual(observables[i].value, expected_value)
            self.assertEqual(len(observables[i].tags), 2)
            self.assertEqual(observables[i].tags[0].fresh, True)
            self.assertEqual(observables[i].tags[1].fresh, True)
        self.assertEqual(unknown[0], "junk")

    def test_refang_ipv4_observable(self) -> None:
        """Tests refanging an ipv4 observable."""
        obs = observable.save(value="1.1.1[.]1")
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.value, "1.1.1.1")
        self.assertEqual(obs.is_valid, True)

    def test_refang_hostname_observable(self) -> None:
        """Tests refanging an hostname observable."""
        obs = observable.save(value="tomchop[.]me")
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.value, "tomchop.me")
        self.assertEqual(obs.is_valid, True)

    def test_refang_email_observable(self) -> None:
        """Tests refanging an email observable."""
        obs = observable.save(value="tom@chop[.]me")
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.value, "tom@chop.me")
        self.assertEqual(obs.is_valid, True)

    def test_refang_url_observable(self) -> None:
        """Tests refanging an url observable."""
        obs = observable.save(value="http://www[.]google[.]com")
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.value, "http://www.google.com")
        self.assertEqual(obs.is_valid, True)

    def test_create_not_stripped_observable(self) -> None:
        """Tests creating an observable that is not stripped."""
        obs = observable.save(value=" hostname.com ")
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.is_valid, True)
        self.assertEqual(obs.value, "hostname.com")

    def test_create_invalid_observable(self) -> None:
        """Tests creating an invalid observable."""
        obs = observable.IPv4(value="192.168.1.258").save()
        self.assertIsNotNone(obs)
        self.assertIsNotNone(obs.id)
        self.assertEqual(obs.is_valid, False)
        self.assertEqual(obs.value, "192.168.1.258")

    def test_count_observables(sefl) -> None:
        """Tests counting observables."""
        observable.save(value="192.168.1.1")
        observable.save(value="tomchop.me")
        observable.save(value="https://www.google.com")
        assert observable.Observable.count() == 3
