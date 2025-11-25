import json
import logging
import urllib.request

import util


class GitlabRepo:
    API_BASE_URL = "https://gitlab.navisense.de/api/v4/projects/96"

    def __init__(self):
        self._logger = logging.getLogger(type(self).__name__)

    def get_semver_tags(self) -> list[util.Semver]:
        """Get tags that are semvers, latest first."""
        semvers = []
        for tag in self.get_tags():
            try:
                semvers.append(util.Semver.parse(tag))
            except ValueError:
                pass
        return sorted(semvers, reverse=True)

    def get_tags(self) -> list[str]:
        url = self.API_BASE_URL + "/repository/tags"
        try:
            with urllib.request.urlopen(url) as response:
                json_response = json.load(response)
            return [tag["name"] for tag in json_response]
        except:
            self._logger.exception("Error getting available tags.")
            return []


_gitlab_repo: GitlabRepo = None


def gitlab_repo() -> GitlabRepo:
    """Get the global instance of GitlabRepo."""
    global _gitlab_repo
    if _gitlab_repo is None:
        _gitlab_repo = GitlabRepo()
    return _gitlab_repo
