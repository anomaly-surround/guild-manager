// Discord webhook validation + embed sender

export function isValidDiscordWebhook(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.hostname !== 'discord.com' && parsed.hostname !== 'discordapp.com') return false;
    // Validate full webhook path format: /api/webhooks/{id}/{token}
    if (!/^\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+$/.test(parsed.pathname)) return false;
    return true;
  } catch { return false; }
}

export async function sendDiscord(webhookUrl, title, description, color) {
  if (!webhookUrl || !isValidDiscordWebhook(webhookUrl)) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{ title: String(title).slice(0, 256), description: String(description).slice(0, 2048), color, footer: { text: 'Guild Manager' }, timestamp: new Date().toISOString() }],
      }),
    });
  } catch (e) { /* ignore */ }
}
