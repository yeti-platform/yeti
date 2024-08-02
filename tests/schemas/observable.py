import datetime
import unittest

from core import database_arango
from core.schemas.graph import Relationship
from core.schemas.observable import Observable
from core.schemas.observables import (
    asn,
    bic,
    certificate,
    cidr,
    command_line,
    docker_image,
    email,
    file,
    generic_observable,
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
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

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
        self.assertEqual(list(result.tags.keys()), ["tag1"])
        self.assertEqual(result.context[0], {"source": "source1", "some": "info"})
        result = registry_key.RegistryKey(
            key="Microsoft\\Windows\\CurrentVersion\\RunOnce",
            value="persist",
            data=b"other.exe",
            hive=registry_key.RegistryHive.HKEY_LOCAL_MACHINE_Software,
        ).save()
        self.assertEqual(result.key, "Microsoft\\Windows\\CurrentVersion\\RunOnce")
        self.assertEqual(result.data, b"other.exe")
        self.assertEqual(list(result.tags.keys()), ["tag1"])
        self.assertEqual(result.context[0], {"source": "source1", "some": "info"})

    def test_create_generic_observable(self):
        result = generic_observable.GenericObservable(value="Some_String").save()
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
        observable = Observable.find(value="toto.com")
        self.assertIsNotNone(observable)
        assert observable is not None
        self.assertEqual(observable.value, "toto.com")  #

        observable = Observable.find(value="tata.com")
        self.assertIsNone(observable)

    def test_observable_get(self) -> None:
        result = hostname.Hostname(value="toto.com").save()
        assert result.id is not None
        observable = Observable.get(result.id)
        assert observable is not None
        self.assertIsNotNone(observable)
        self.assertEqual(observable.value, "toto.com")

    def test_observable_filter(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        obs2 = hostname.Hostname(value="test2.com").save()

        result, total = Observable.filter(query_args={"value": "test"})
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        self.assertEqual(result[0].id, obs1.id)
        self.assertEqual(result[0].value, "test1.com")
        self.assertEqual(result[1].id, obs2.id)
        self.assertEqual(result[1].value, "test2.com")

    def test_observable_filter_in(self):
        obs1 = hostname.Hostname(value="test1.com").save()
        hostname.Hostname(value="test2.com").save()
        obs3 = hostname.Hostname(value="test3.com").save()

        result, total = Observable.filter(
            query_args={"value__in": ["test1.com", "test3.com"]}
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(total, 2)
        self.assertEqual(result[0].id, obs1.id)
        self.assertEqual(result[0].value, "test1.com")
        self.assertEqual(result[1].id, obs3.id)
        self.assertEqual(result[1].value, "test3.com")

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
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source2", {"abc": 123, "def": 456})

        assert observable.id is not None
        observable = Observable.get(observable.id)
        self.assertEqual(len(observable.context), 2)
        self.assertEqual(observable.context[0]["abc"], 123)
        self.assertEqual(observable.context[0]["source"], "test_source")
        self.assertEqual(observable.context[1]["abc"], 123)
        self.assertEqual(observable.context[1]["source"], "test_source2")

    def test_add_dupe_context(self) -> None:
        """Tests that identical contexts aren't added twice."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 456})
        self.assertEqual(len(observable.context), 1)

    def test_add_new_context_with_same_source(self) -> None:
        """Tests that diff contexts with same source are added separately."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 666})
        self.assertEqual(len(observable.context), 2)

    def test_add_multiple_contexts_with_same_source(self) -> None:
        """Tests that two different contexts can be added from the same source."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 666})
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 123, "def": 666})
        self.assertEqual(len(observable.context), 2)
        self.assertEqual(
            observable.context[0], {"source": "test_source", "abc": 123, "def": 456}
        )
        self.assertEqual(
            observable.context[1], {"source": "test_source", "abc": 123, "def": 666}
        )

    def test_add_new_context_with_same_source_and_ignore_field(self) -> None:
        """Tests that the context is updated if the difference is not being
        compared."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 999, "def": 456})
        observable.add_context(
            "test_source", {"abc": 123, "def": 666}, skip_compare={"def"}
        )
        self.assertEqual(len(observable.context), 2)
        self.assertEqual(observable.context[0]["def"], 666)
        self.assertEqual(observable.context[1]["abc"], 999)

    def test_overwrite_context(self) -> None:
        """Tests that one or more contexts is added and persisted in the DB."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable.add_context("test_source", {"abc": 123, "def": 456})
        observable.add_context("test_source", {"abc": 456, "def": 123}, overwrite=True)

        assert observable.id is not None
        observable = Observable.get(observable.id)
        self.assertEqual(len(observable.context), 1)
        self.assertEqual(observable.context[0]["abc"], 456)
        self.assertEqual(observable.context[0]["def"], 123)
        self.assertEqual(observable.context[0]["source"], "test_source")

    def test_delete_context(self) -> None:
        """Tests that a context is deleted if contents fully match."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context("test_source", {"def": 456, "abc": 123})
        assert observable.id is not None
        observable = Observable.get(observable.id)  # type: ignore

        self.assertEqual(len(observable.context), 0)

    def test_delete_context_diff(self) -> None:
        """Tests that a context is not deleted if contents don't match."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context("test_source", {"def": 456, "abc": 000})
        observable = Observable.get(observable.id)  # type: ignore
        self.assertEqual(len(observable.context), 1)

    def tests_delete_context_skip_compare(self) -> None:
        """Tests that a context is deleted if the difference is not being
        compared."""
        observable = hostname.Hostname(value="tomchop.me").save()
        observable = observable.add_context("test_source", {"abc": 123, "def": 456})
        observable = observable.delete_context(
            "test_source", {"abc": 000, "def": 456}, skip_compare={"abc"}
        )
        observable = Observable.get(observable.id)  # type: ignore
        self.assertEqual(len(observable.context), 0)

    def test_duplicate_value(self) -> None:
        """Tests saving two observables with the same value return the same observable."""
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop.me").save()
        self.assertEqual(obs1.id, obs2.id)

    def test_create_asn(self) -> None:
        """Tests creating an ASN."""
        observable = asn.ASN(value="AS123").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "AS123")
        self.assertIsInstance(observable, asn.ASN)

    def test_create_wallet(self) -> None:
        """Tests creating a wallet."""
        observable = wallet.Wallet(
            value="btc/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            coin="btc",
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ).save()
        self.assertIsInstance(observable, wallet.Wallet)
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "btc/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertEqual(observable.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertEqual(observable.coin, "btc")

    def test_create_certificate(self) -> None:
        """Tests creating a certificate."""
        observable = certificate.Certificate.from_data(b"1234").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(
            observable.value,
            "CERT:03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
        )
        self.assertIsInstance(observable, certificate.Certificate)

    def test_create_cidr(self) -> None:
        """Tests creating a CIDR."""
        observable = cidr.CIDR(value="0.0.0.0/0").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "0.0.0.0/0")
        self.assertIsInstance(observable, cidr.CIDR)

    def test_create_command_line(self) -> None:
        """Tests creating a command line."""
        observable = command_line.CommandLine(value="ls -la").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "ls -la")
        self.assertIsInstance(observable, command_line.CommandLine)

    def test_create_docker_image(self) -> None:
        """Tests creating a docker image."""
        observable = docker_image.DockerImage(value="yetiplatform/yeti:latest").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "yetiplatform/yeti:latest")
        self.assertIsInstance(observable, docker_image.DockerImage)

    def test_create_email(self) -> None:
        """Tests creating an email."""
        observable = email.Email(value="example@gmail.com").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "example@gmail.com")
        self.assertIsInstance(observable, email.Email)

    def test_create_file(self) -> None:
        """Tests creating a file."""
        observable = file.File(value="FILE:HASH").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "FILE:HASH")
        self.assertIsInstance(observable, file.File)

    def test_create_hostname(self) -> None:
        """Tests creating a hostname."""
        observable = hostname.Hostname(value="tomchop.me").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "tomchop.me")
        self.assertIsInstance(observable, hostname.Hostname)

    def test_create_imphash(self) -> None:
        """Tests creating an imphash."""
        observable = imphash.Imphash(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, imphash.Imphash)

    def test_create_mutex(self) -> None:
        """Tests creating a mutex."""
        mutex_obs = mutex.Mutex(value="test_mutex").save()
        self.assertIsNotNone(mutex_obs.id)
        self.assertEqual(mutex_obs.value, "test_mutex")

    def test_create_named_pipe(self) -> None:
        """Tests creating a name pipe."""
        observable = named_pipe.NamedPipe(value="\\\\.\\pipe\\test").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "\\\\.\\pipe\\test")

    def test_create_ipv4(self) -> None:
        """Tests creating an IPv4."""
        observable = ipv4.IPv4(value="127.0.0.1").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "127.0.0.1")
        self.assertIsInstance(observable, ipv4.IPv4)

    def test_create_ipv6(self) -> None:
        """Tests creating an IPv6."""
        observable = ipv6.IPv6(value="::1").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "::1")
        self.assertIsInstance(observable, ipv6.IPv6)

    def test_create_ja3(self) -> None:
        """Tests creating a JA3."""
        observable = ja3.JA3(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertEqual(observable.type, "ja3")

    def test_create_mac_address(self) -> None:
        """Tests creating a MAC address."""
        observable = mac_address.MacAddress(value="00:00:00:00:00:00").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "00:00:00:00:00:00")
        self.assertIsInstance(observable, mac_address.MacAddress)

    def test_create_iban(self) -> None:
        """Tests creating an IBAN."""
        observable = iban.IBAN(value="GB33BUKB20201555555555").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "GB33BUKB20201555555555")
        self.assertIsInstance(observable, iban.IBAN)

    def test_create_bic(self) -> None:
        """Tests creating a BIC."""
        observable = bic.BIC(value="BUKBGB22XXX").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "BUKBGB22XXX")
        self.assertIsInstance(observable, bic.BIC)

    def test_create_md5(self) -> None:
        """Tests creating an MD5."""
        observable = md5.MD5(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, md5.MD5)

    def test_create_path(self) -> None:
        """Tests creating a path."""
        observable = path.Path(value="/var/test").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "/var/test")
        self.assertIsInstance(observable, path.Path)

    def test_create_registry_key(self) -> None:
        """Tests creating a registry key."""
        observable = registry_key.RegistryKey(
            key="Microsoft\\Windows\\CurrentVersion\\Run",
            value="persist",
            data=b"cmd.exe",
            hive=registry_key.RegistryHive.HKEY_LOCAL_MACHINE_Software,
        ).save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "persist")
        self.assertIsInstance(observable, registry_key.RegistryKey)

    def test_create_sha1(self) -> None:
        """Tests creating a SHA1."""
        observable = sha1.SHA1(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, sha1.SHA1)

    def test_create_sha256(self) -> None:
        """Tests creating a SHA256."""
        observable = sha256.SHA256(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, sha256.SHA256)

    def test_create_ssdeep(self) -> None:
        """Tests creating an ssdeep."""
        observable = ssdeep.SsdeepHash(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, ssdeep.SsdeepHash)

    def test_create_tlsh(self) -> None:
        """Tests creating a TLSH."""
        observable = tlsh.TLSH(value="1234567890").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "1234567890")
        self.assertIsInstance(observable, tlsh.TLSH)

    def test_create_url(self) -> None:
        """Tests creating a URL."""
        observable = url.Url(value="https://www.google.com").save()
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "https://www.google.com")
        self.assertIsInstance(observable, url.Url)

    def test_create_user_agent(self) -> None:
        """Tests creating a user agent."""
        observable = user_agent.UserAgent(
            value="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ).save()  # noqa: E501
        self.assertIsNotNone(observable.id)
        self.assertEqual(
            observable.value,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        )  # noqa: E501
        self.assertIsInstance(observable, user_agent.UserAgent)

    def test_create_user_account(self) -> None:
        """Tests creating a user account."""
        observable = user_account.UserAccount(
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
        self.assertIsNotNone(observable.id)
        self.assertEqual(observable.value, "test_account")
        self.assertIsInstance(observable, user_account.UserAccount)
        self.assertEqual(observable.user_id, "test_user_id")
        self.assertEqual(observable.credential, "test_credential")
        self.assertEqual(observable.account_login, "test_account_login")
        self.assertEqual(observable.account_type, "test_account_type")
        self.assertEqual(observable.display_name, "test_display_name")
        self.assertEqual(observable.is_service_account, True)
        self.assertEqual(observable.is_privileged, True)
        self.assertEqual(observable.can_escalate_privs, True)
        self.assertEqual(observable.is_disabled, True)
        self.assertEqual(
            observable.account_created,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable.account_expires,
            datetime.datetime(2023, 12, 31, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable.credential_last_changed,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable.account_first_login,
            datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            observable.account_last_login,
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
