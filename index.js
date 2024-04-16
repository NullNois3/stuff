const verifySlackSignature = (event) => {
  const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
  const request_body = event.body;
  const timestamp = event.headers['X-Slack-Request-Timestamp'];
  const slackSignature = event.headers['X-Slack-Signature'];

  // Prevent replay attacks by checking that the timestamp is recent
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 60 * 5) {
    return false;
  }

  const sigBasestring = `v0:${timestamp}:${request_body}`;
  const mySignature = 'v0=' + crypto.createHmac('sha256', slackSigningSecret)
                                    .update(sigBasestring)
                                    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(mySignature, 'utf8'), Buffer.from(slackSignature, 'utf8'));
};
