export type SecretPattern = {
  id: string
  name: string
  severity: "critical" | "high" | "medium"
  description: string
  regex: RegExp
}

/**
 * Curated list of secret detection patterns.
 * Focus: high-confidence, commonly leaked credentials.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    severity: "critical",
    description: "Amazon Web Services access key. Grants programmatic access to AWS resources.",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    severity: "critical",
    description: "AWS secret key paired with an access key ID. Full compromise if leaked.",
    regex: /\baws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/gi,
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    severity: "critical",
    description: "Classic GitHub token granting repo, user, and potentially admin access.",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    name: "GitHub Fine-Grained Token",
    severity: "critical",
    description: "Newer GitHub token with scoped permissions.",
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
  },
  {
    id: "github-oauth",
    name: "GitHub OAuth Token",
    severity: "critical",
    description: "OAuth access token issued by GitHub.",
    regex: /\bgho_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: "stripe-live-key",
    name: "Stripe Live Secret Key",
    severity: "critical",
    description: "Stripe production secret key. Can charge real cards.",
    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,
  },
  {
    id: "stripe-test-key",
    name: "Stripe Test Secret Key",
    severity: "medium",
    description: "Stripe test key. Lower risk but still should not be public.",
    regex: /\bsk_test_[0-9a-zA-Z]{24,}\b/g,
  },
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    severity: "critical",
    description: "OpenAI API key. Can incur significant usage charges.",
    regex: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "google-api-key",
    name: "Google API Key",
    severity: "high",
    description: "Google Cloud / Firebase API key.",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "slack-token",
    name: "Slack Token",
    severity: "high",
    description: "Slack bot, user, or workspace token.",
    regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g,
  },
  {
    id: "slack-webhook",
    name: "Slack Webhook URL",
    severity: "medium",
    description: "Slack incoming webhook. Allows posting to channels.",
    regex: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+\b/g,
  },
  {
    id: "private-key",
    name: "Private Key (RSA / SSH / PGP)",
    severity: "critical",
    description: "Private cryptographic key. Should never be committed.",
    regex: /-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/g,
  },
  {
    id: "jwt",
    name: "JSON Web Token (JWT)",
    severity: "medium",
    description: "Possible JWT. May or may not be sensitive depending on contents.",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: "generic-password-in-url",
    name: "Password in Connection String",
    severity: "high",
    description: "Database or service URL with embedded password.",
    regex: /\b(mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^\s:@]+:[^\s@]+@[^\s]+/gi,
  },
  {
    id: "sendgrid-key",
    name: "SendGrid API Key",
    severity: "high",
    description: "SendGrid email API key.",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  },
  {
    id: "twilio-key",
    name: "Twilio API Key / SID",
    severity: "high",
    description: "Twilio account SID or API key.",
    regex: /\bAC[a-f0-9]{32}\b|\bSK[a-f0-9]{32}\b/g,
  },
]