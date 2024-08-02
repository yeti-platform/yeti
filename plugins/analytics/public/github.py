import hashlib
import json
import logging
from datetime import timedelta

from github import Auth, Github

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import indicator, observable, task
from core.schemas.observable import ObservableType


class GithubMonitor(task.AnalyticsTask):
    """GithubMonitor analytics monitors Github repositories and code based on queries indicators of type github.

    The query must be a list of dictionary with the following keys:
    - type: code or repositories
    - query: the query to search for

    Example:
    [
       {"type": "code", "query": "password"},
       {"type": "repositories", "query": in:readme HelloWold"}
    ]

    GithubMonitor will search for the query in the Github API and create observables for the code and repositories found
    and create relationships between the indicator and the observables found.
    """

    _defaults = {
        "name": "GithubMonitor",
        "description": "Executes Github queries (stored as indicators) and create relevant observables.",
        "frequency": timedelta(hours=24),
    }

    def _get_or_create_observable(self, obs_type, value):
        cls = observable.TYPE_MAPPING[obs_type]
        obs = cls.find(value=value)
        if not obs:
            obs = cls(value=value).save()
        return obs

    def create_code_observable(self, code, query, tags):
        logging.info(f"Processing code: {code.path}")
        md5 = hashlib.md5(code.decoded_content).hexdigest()
        sha1 = hashlib.sha1(code.decoded_content).hexdigest()
        sha256 = hashlib.sha256(code.decoded_content).hexdigest()
        value = f"{code.path}:{sha256}"
        context = {
            "content": f"{code.decoded_content.decode('utf-8')}",
            "path": code.path,
            "url": code.url,
            "download_url": code.download_url,
        }
        code_obs = self._get_or_create_observable(ObservableType.file, value)
        code_obs.md5 = md5
        code_obs.sha1 = hashlib.sha1(code.decoded_content).hexdigest()
        code_obs.sha256 = sha256
        code_obs.size = code.size
        code_obs.tag(tags + ["github-code"])
        code_obs.add_context(self.name, context)
        code_obs.save()
        md5_obs = self._get_or_create_observable(ObservableType.md5, md5)
        sha1_obs = self._get_or_create_observable(ObservableType.sha1, sha1)
        sha256_obs = self._get_or_create_observable(ObservableType.sha256, sha256)
        md5_obs.tag(tags + ["github-code"])
        sha1_obs.tag(tags + ["github-code"])
        sha256_obs.tag(tags + ["github-code"])
        code_obs.link_to(md5_obs, "md5", "")
        code_obs.link_to(sha1_obs, "sha1", "")
        code_obs.link_to(sha256_obs, "sha256", "")
        return code_obs.save()

    def create_repository_observable(self, repository, query, tags):
        logging.info(f"Processing repository: {repository.html_url}")
        repository_obs = self._get_or_create_observable(
            ObservableType.url, repository.html_url
        )
        repository_obs.tag(tags + ["github-repository"])
        context = {
            "description": repository.description,
            "branches": [branch.name for branch in repository.get_branches()],
            "id": repository.id,
            "fullname": repository.full_name,
            "last modified": repository.last_modified,
            "pushed at": repository.pushed_at,
            "created at": repository.created_at,
            "stars": repository.stargazers_count,
            "subscribers": repository.subscribers_count,
            "forks": repository.forks_count,
            "watchers": repository.watchers_count,
            "matching query": query,
        }
        repository_obs.add_context(self.name, context)
        return repository_obs.save()

    def create_user_observable(self, owner, tags):
        logging.info(f"Processing owner: {owner.html_url}")
        user_obs = self._get_or_create_observable(
            ObservableType.user_account, owner.login
        )
        user_obs.user_id = str(owner.id)
        user_obs.account_login = owner.login
        user_obs.account_type = "github"
        user_obs.display_name = owner.name
        user_obs.account_created = owner.created_at
        user_obs.tag(tags + ["github-user"])
        user_obs.created = owner.created_at
        context = {"bio": owner.bio, "email": owner.email, "url": owner.html_url}
        user_obs.add_context(self.name, context)
        return user_obs.save()

    def handle_code_search(self, indicator, query, tags):
        logging.info(f"[+] Searching code with {query}")
        for code in self.__github_api.search_code(query):
            code_obs = self.create_code_observable(code, query, tags)
            repository_obs = self.create_repository_observable(
                code.repository, query, tags
            )
            owner_obs = self.create_user_observable(code.repository.owner, tags)
            owner_obs.link_to(repository_obs, "owns", "")
            repository_obs.link_to(code_obs, "contains", f"matches {query}")
            indicator.link_to(code_obs, "matches", f"matches {query}")
            indicator.link_to(repository_obs, "contains", f"matched file {query}")

    def handle_repositories_search(self, indicator, query, tags):
        logging.info(f"[+] Searching repositories with {query}")
        for repository in self.__github_api.search_repositories(query):
            repository_obs = self.create_repository_observable(repository, query, tags)
            owner_obs = self.create_user_observable(repository.owner, tags)
            owner_obs.link_to(repository_obs, "owns", "")
            indicator.link_to(repository_obs, "matches", f"matches {query}")

    def run(self):
        github_token = yeti_config.get("github", "token")

        auth = Auth.Token(github_token)
        self.__github_api = Github(auth=auth)

        github_queries, _ = indicator.Query.filter({"query_type": "github"})
        logging.info(
            f"[+] Found {len(github_queries)} Github queries: {github_queries}"
        )

        try:
            for queries in github_queries:
                for query in json.loads(queries.pattern):
                    handler = getattr(self, f"handle_{query['type']}_search")
                    if not handler:
                        logging.error(f"Unknown query type {query['type']}")
                        continue
                    handler(queries, query["query"], list(queries.relevant_tags))
        finally:
            self.__github_api.close()


taskmanager.TaskManager.register_task(GithubMonitor)
