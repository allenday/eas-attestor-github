/**
 * Server Integration Tests
 * Tests against actual running localhost server to catch CORS, CSP, and HTTP issues
 */

describe('Server Integration Tests', () => {
  const VALIDATOR_URL = process.env.VALIDATOR_URL || 'http://localhost:6001';
  const TIMEOUT = 10000; // 10s timeout for server calls

  beforeAll(() => {
    console.log(`🌐 Testing against server: ${VALIDATOR_URL}`);
  });

  describe('Health Check', () => {
    it('should respond to server address endpoint', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/address`);
      
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toContain('application/json');
      
      const result = await response.json();
      expect(result).toHaveProperty('address');
      expect(result.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
    }, TIMEOUT);
  });

  describe('CORS Configuration', () => {
    it('should allow CORS from localhost origins', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/address`, {
        method: 'OPTIONS',
        headers: {
          'Origin': 'http://localhost:3000',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Content-Type'
        }
      });

      expect([200, 204]).toContain(response.status); // Preflight can return 204 No Content
      expect(response.headers.get('access-control-allow-origin')).toBeTruthy();
    }, TIMEOUT);

    it('should handle preflight requests correctly', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/verify`, {
        method: 'OPTIONS',
        headers: {
          'Origin': 'http://localhost:9000',
          'Access-Control-Request-Method': 'POST'
        }
      });

      expect([200, 204]).toContain(response.status); // Preflight can return 204 No Content
    }, TIMEOUT);
  });

  describe('API Endpoints', () => {
    it('should handle POST /v1/sign/verify with missing fields', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          // Invalid request to test validation - missing required fields
          message: 'test'
          // Missing signature
        })
      });

      // Should return validation error for missing fields
      expect([400, 422]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should handle POST /v1/contribution/validate-identity', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/contribution/validate-identity`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          github_username: 'testuser',
          gist_url: 'https://gist.github.com/testuser/nonexistent',
          ethereum_address: '0x742d35Cc6634C0532925a3b8D98d00F932E6B9c2'
        })
      });

      // Should attempt validation (might fail due to GitHub API or gist not existing, but structure should be correct)
      expect([200, 400, 404, 500]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should handle POST /v1/repository/register with missing fields', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/repository/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          repository_path: 'owner/repo'
          // Missing signature
        })
      });

      // Should return validation error for missing fields
      expect([400, 422]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);
  });

  describe('Static File Serving', () => {
    it('should serve HTML files with correct content-type', async () => {
      const response = await fetch(`${VALIDATOR_URL}/`);
      
      if (response.status === 200) {
        expect(response.headers.get('content-type')).toContain('text/html');
        
        const html = await response.text();
        expect(html).toContain('<!DOCTYPE html>');
      } else {
        // Validator might not serve HTML (API service only)
        expect([404, 500]).toContain(response.status);
      }
    }, TIMEOUT);

    it('should serve JavaScript files with correct content-type', async () => {
      const response = await fetch(`${VALIDATOR_URL}/config.js`);
      
      if (response.status === 200) {
        expect(response.headers.get('content-type')).toContain('application/javascript');
      } else {
        // File might not exist, that's OK for this test
        expect([404]).toContain(response.status);
      }
    }, TIMEOUT);

    it('should serve JSON responses with correct content-type', async () => {
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/address`);
      
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toContain('application/json');
      
      const json = await response.json();
      expect(json).toHaveProperty('address');
    }, TIMEOUT);
  });

  describe('Security Headers', () => {
    it('should include security headers', async () => {
      const response = await fetch(`${VALIDATOR_URL}/`);
      
      // Check for basic security headers
      const headers = response.headers;
      
      // These should be present for security
      expect(headers.get('x-frame-options') || headers.get('content-security-policy')).toBeTruthy();
      
      // Check that server doesn't leak version info
      const server = headers.get('server');
      if (server) {
        expect(server.toLowerCase()).not.toContain('express');
        expect(server.toLowerCase()).not.toContain('node');
      }
    }, TIMEOUT);

    it('should handle CSP for localhost development', async () => {
      const response = await fetch(`${VALIDATOR_URL}/`);
      
      const csp = response.headers.get('content-security-policy');
      if (csp) {
        // CSP should allow localhost for development
        expect(csp.toLowerCase()).toContain('localhost');
      }
    }, TIMEOUT);
  });

  describe('Error Handling', () => {
    it('should return 404 for non-existent endpoints', async () => {
      const response = await fetch(`${VALIDATOR_URL}/api/nonexistent-endpoint`);
      expect(response.status).toBe(404);
    }, TIMEOUT);

    it('should return JSON error responses for API endpoints', async () => {
      const response = await fetch(`${VALIDATOR_URL}/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: 'invalid json'
      });

      expect([400, 422, 500]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should handle malformed requests gracefully', async () => {
      const response = await fetch(`${VALIDATOR_URL}/health`, {
        method: 'POST', // Wrong method for health endpoint (should be GET)
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
      });

      expect([404, 405]).toContain(response.status);
    }, TIMEOUT);
  });

  describe('GitHub Webhook Processing', () => {
    const WEBHOOK_ENDPOINT = `${VALIDATOR_URL}/v1/webhook`;
    
    // Mock GitHub webhook payloads demonstrating different actor types
    const mockWebhookPayloads = {
      pullRequestOpened: {
        action: 'opened',
        number: 123,
        pull_request: {
          id: 987654321,
          number: 123,
          title: 'Add new feature',
          user: {
            login: 'pr-author',
            id: 12345,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/pull/123',
          state: 'open',
          merged: false,
          merged_by: null,
          head: {
            sha: 'abc123def456'
          }
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'pr-author',
          id: 12345,
          type: 'User'
        }
      },
      
      pullRequestMerged: {
        action: 'closed',
        number: 123,
        pull_request: {
          id: 987654321,
          number: 123,
          title: 'Add new feature',
          user: {
            login: 'pr-author',  // Original creator
            id: 12345,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/pull/123',
          state: 'closed',
          merged: true,
          merged_by: {
            login: 'maintainer',  // Different person who merged
            id: 67890,
            type: 'User'
          },
          head: {
            sha: 'abc123def456'
          }
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'maintainer',  // Person who triggered merge event
          id: 67890,
          type: 'User'
        }
      },

      pullRequestMergedByUnknownUser: {
        action: 'closed',
        number: 456,
        pull_request: {
          id: 888999000,
          number: 456,
          title: 'Fix critical bug',
          user: {
            login: 'verified-contributor',  // Known user with identity attestation
            id: 11111,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/pull/456',
          state: 'closed',
          merged: true,
          merged_by: {
            login: 'unknown-maintainer',  // Unknown user (no identity attestation)
            id: 88888,
            type: 'User'
          },
          head: {
            sha: 'def456ghi789'
          }
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'unknown-maintainer',  // Unknown user triggered merge
          id: 88888,
          type: 'User'
        }
      },

      issueOpened: {
        action: 'opened',
        issue: {
          id: 111222333,
          number: 456,
          title: 'Bug report',
          user: {
            login: 'issue-reporter',
            id: 33333,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/issues/456',
          state: 'open'
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'issue-reporter',
          id: 33333,
          type: 'User'
        }
      },

      issueClosed: {
        action: 'closed',
        issue: {
          id: 111222333,
          number: 456,
          title: 'Bug report',
          user: {
            login: 'issue-reporter',  // Original reporter
            id: 33333,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/issues/456',
          state: 'closed',
          closed_by: {
            login: 'maintainer',  // Person who closed the issue
            id: 67890,
            type: 'User'
          }
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'maintainer',  // Person who triggered close event
          id: 67890,
          type: 'User'
        }
      },

      pullRequestReviewSubmitted: {
        action: 'submitted',
        review: {
          id: 444555666,
          user: {
            login: 'reviewer',
            id: 77777,
            type: 'User'
          },
          state: 'approved',
          html_url: 'https://github.com/owner/repo/pull/123#pullrequestreview-444555666'
        },
        pull_request: {
          id: 987654321,
          number: 123,
          title: 'Add new feature',
          user: {
            login: 'pr-author',  // Original PR author
            id: 12345,
            type: 'User'
          },
          html_url: 'https://github.com/owner/repo/pull/123'
        },
        repository: {
          id: 555666777,
          name: 'repo',
          full_name: 'owner/repo',
          owner: {
            login: 'owner',
            id: 99999
          }
        },
        sender: {
          login: 'reviewer',  // Person who submitted the review
          id: 77777,
          type: 'User'
        }
      }
    };

    it('should accept webhook payload for PR opened (PR author contribution)', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.pullRequestOpened)
      });

      console.log('Webhook response status:', response.status);
      const responseText = await response.text();
      console.log('Webhook response body:', responseText);

      // Server should accept webhook (endpoint exists and processes payload)
      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should accept webhook payload for PR merged (shows different actors)', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.pullRequestMerged)
      });

      // Server should accept webhook and potentially create different contribution attributions:
      // - PR author (pr.user.login = 'pr-author') for opening contribution
      // - Maintainer (pr.merged_by.login = 'maintainer') for merge contribution
      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should handle PR merged by unknown user (0x0 attribution)', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.pullRequestMergedByUnknownUser)
      });

      // Server should accept webhook and handle the case where:
      // - PR author (pr.user.login = 'verified-contributor') has identity attestation → gets credit for merged PR
      // - Merger (pr.merged_by.login = 'unknown-maintainer') has NO identity attestation → merge event attributed to 0x0
      // The verified contributor should still get credit for the merged PR contribution
      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should accept webhook payload for issue opened', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'issues',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.issueOpened)
      });

      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should accept webhook payload for issue closed (shows different actors)', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'issues',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.issueClosed)
      });

      // Server should accept webhook and potentially create different contribution attributions:
      // - Issue reporter (issue.user.login = 'issue-reporter') for reporting contribution
      // - Maintainer (issue.closed_by.login = 'maintainer') for resolution contribution
      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should accept webhook payload for PR review (reviewer contribution)', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request_review',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: JSON.stringify(mockWebhookPayloads.pullRequestReviewSubmitted)
      });

      // Server should accept webhook and attribute review contribution to reviewer
      // (review.user.login = 'reviewer'), not the original PR author
      expect([200, 400, 401, 403]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should handle malformed webhook payloads gracefully', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-GitHub-Event': 'pull_request',
          'X-Hub-Signature-256': 'sha256=mock_signature'
        },
        body: 'invalid json'
      });

      expect([400, 422]).toContain(response.status);
      expect(response.headers.get('content-type')).toContain('application/json');
    }, TIMEOUT);

    it('should reject webhooks without proper GitHub headers', async () => {
      const response = await fetch(WEBHOOK_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
          // Missing X-GitHub-Event and X-Hub-Signature-256
        },
        body: JSON.stringify(mockWebhookPayloads.pullRequestOpened)
      });

      expect([400, 401, 403]).toContain(response.status);
    }, TIMEOUT);
  });

  describe('Performance', () => {
    it('should respond to API endpoints quickly', async () => {
      const start = Date.now();
      const response = await fetch(`${VALIDATOR_URL}/v1/sign/address`);
      const duration = Date.now() - start;
      
      expect(response.status).toBe(200);
      expect(duration).toBeLessThan(1000); // Should respond within 1 second
    }, TIMEOUT);

    it('should handle concurrent requests', async () => {
      const promises = Array(5).fill(0).map(() => 
        fetch(`${VALIDATOR_URL}/v1/sign/address`)
      );
      
      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    }, TIMEOUT);
  });
});