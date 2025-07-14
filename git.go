package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-github/v72/github"
	"golang.org/x/oauth2"
)

// extractToken retrieves the token from the repository URL, if present.
func extractToken(u *url.URL) string {
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok {
			return pwd
		}
	}
	return ""
}

// extractOwnerRepo parses the owner and repository name from the URL path.
func extractOwnerRepo(u *url.URL) (string, string, error) {
	parts := strings.Split(strings.TrimSuffix(u.Path, ".git"), "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid repository path")
	}
	return parts[1], parts[2], nil
}

// createGitHubClient initializes the GitHub client, authenticated if a token is
// provided.
func createGitHubClient(ctx context.Context, token string) *github.Client {
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		})
		tc := oauth2.NewClient(ctx, ts)
		return github.NewClient(tc)
	}
	return github.NewClient(nil)
}

// isIssueExist searches the specified GitHub repository for an issue with the
// exact title. If an error occurs during the search, it returns false.
func isIssueExist(ctx context.Context, client *github.Client, owner, repo,
	targetTitle string, logger *slog.Logger) bool {

	logger.Info("Searching for existing issue",
		"owner", owner,
		"repo", repo,
		"title", targetTitle,
	)

	// Build a search query that restricts to this repo and the exact title
	query := fmt.Sprintf(`repo:%s/%s is:issue "%s"`, owner, repo,
		targetTitle)

	// Perform the search
	results, _, err := client.Search.Issues(ctx, query,
		&github.SearchOptions{})
	if err != nil {
		logger.Error("GitHub issue search failed",
			"query", query,
			"error", err,
		)
		return false
	}

	if len(results.Issues) != 0 {
		logger.Info("Issue already exists", "url",
			results.Issues[0].GetHTMLURL())

		return true
	}
	return false
}

// createIssue creates a new GitHub issue in the specified repository with the
// given title and body.
func createIssue(ctx context.Context, client *github.Client, owner, repo, title,
	body string, logger *slog.Logger) error {

	logger.Info("Creating new issue",
		"owner", owner,
		"repo", repo,
		"title", title,
	)

	issueRequest := &github.IssueRequest{
		Title: &title,
		Body:  &body,
	}

	issue, _, err := client.Issues.Create(ctx, owner, repo, issueRequest)
	if err != nil {
		return err
	}

	logger.Info("Issue created successfully", "url", issue.GetHTMLURL())

	return nil
}
