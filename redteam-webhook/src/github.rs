use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct PullRequestEvent {
    pub action: String,
    pub pull_request: PullRequest,
    pub repository: Repository,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PullRequest {
    pub number: i64,
    pub head: CommitRef,
    pub base: CommitRef,
    pub html_url: String,
    pub title: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitRef {
    pub sha: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Repository {
    pub full_name: String,
    pub clone_url: String,
    pub html_url: String,
}
