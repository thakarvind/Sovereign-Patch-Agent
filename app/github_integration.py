"""
Sovereign Patch Agent — GitHub Integration
============================================
Production GitHub API client for PR staging, branch management,
and repository operations.
"""

import logging
import os

logger = logging.getLogger("SovereignPatchAgent.GitHub")


class GitHubClient:
    """Client for interacting with the GitHub REST API v3."""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.headers = {
            "Authorization": f"token {self.token}" if self.token else "",
            "Accept": "application/vnd.github.v3+json",
        }
        self.base_url = "https://api.github.com"

    @property
    def is_configured(self) -> bool:
        """Check if GitHub token is configured."""
        return bool(self.token)

    def create_pull_request(
        self, repo: str, branch: str, title: str, body: str
    ) -> str:
        """Create a pull request on GitHub.

        Args:
            repo: Repository in 'owner/repo' format.
            branch: Source branch for the PR.
            title: PR title.
            body: PR description.

        Returns:
            HTML URL of the created PR, or a simulation message if no token.
        """
        if not self.is_configured:
            logger.warning(
                "GITHUB_TOKEN not set — simulating PR creation. "
                "Set GITHUB_TOKEN in .env for production use."
            )
            return (
                f"[SIMULATED] PR staged: '{title}' from {branch} → main "
                f"on {repo}"
            )

        try:
            import requests

            url = f"{self.base_url}/repos/{repo}/pulls"
            payload = {
                "title": title,
                "head": branch,
                "base": "main",
                "body": body,
            }
            response = requests.post(
                url, headers=self.headers, json=payload
            )
            response.raise_for_status()
            pr_url = response.json().get("html_url", "URL not available")
            logger.info(f"PR created successfully: {pr_url}")
            return pr_url
        except Exception as e:
            logger.error(f"Failed to create PR: {e}")
            return f"[ERROR] PR creation failed: {e}"

    def get_repo_info(self, repo: str) -> dict:
        """Get basic repository information.

        Args:
            repo: Repository in 'owner/repo' format.

        Returns:
            Dict with repo info or error details.
        """
        if not self.is_configured:
            return {"status": "SIMULATED", "repo": repo}

        try:
            import requests

            url = f"{self.base_url}/repos/{repo}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            return {
                "name": data.get("full_name"),
                "default_branch": data.get("default_branch"),
                "open_issues": data.get("open_issues_count"),
                "visibility": data.get("visibility"),
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}
