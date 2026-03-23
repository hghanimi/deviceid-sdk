const crypto = require('crypto');

class IdentityGraph {

  constructor(db) {
    this.db = db;
  }

  async linkDevices(visitorIdA, visitorIdB, linkType, confidence, evidence, apiKeyId) {
    const [a, b] = [visitorIdA, visitorIdB].sort();
    await this.db.query(`
      INSERT INTO device_links
        (visitor_id_a, visitor_id_b, link_type, confidence, evidence, api_key_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (visitor_id_a, visitor_id_b, api_key_id)
      DO UPDATE SET confidence = GREATEST(device_links.confidence, $4),
                    evidence = device_links.evidence || $5
    `, [a, b, linkType, confidence, JSON.stringify(evidence), apiKeyId]);
  }

  async getLinkedDevices(visitorId, apiKeyId) {
    const result = await this.db.query(`
      WITH RECURSIVE linked AS (
        SELECT visitor_id_b AS linked_id, confidence, 1 AS depth
        FROM device_links
        WHERE visitor_id_a = $1 AND api_key_id = $2
        UNION
        SELECT visitor_id_a AS linked_id, dl.confidence, 1 AS depth
        FROM device_links dl
        WHERE visitor_id_b = $1 AND api_key_id = $2
        UNION
        SELECT
          CASE WHEN dl.visitor_id_a = l.linked_id
               THEN dl.visitor_id_b ELSE dl.visitor_id_a END,
          LEAST(l.confidence, dl.confidence),
          l.depth + 1
        FROM device_links dl
        JOIN linked l ON (dl.visitor_id_a = l.linked_id OR dl.visitor_id_b = l.linked_id)
        WHERE dl.api_key_id = $2 AND l.depth < 2
      )
      SELECT DISTINCT linked_id, MAX(confidence) as confidence
      FROM linked WHERE linked_id != $1
      GROUP BY linked_id
    `, [visitorId, apiKeyId]);
    return result.rows;
  }

  async fireWebhooks(apiKeyId, eventData) {
    const hooks = await this.db.query(
      `SELECT * FROM webhooks WHERE api_key_id = $1 AND is_active = true AND $2 = ANY(events)`,
      [apiKeyId, eventData.event]
    );

    for (const hook of hooks.rows) {
      try {
        const payload = JSON.stringify(eventData);
        const signature = crypto
          .createHmac('sha256', hook.secret)
          .update(payload)
          .digest('hex');

        await fetch(hook.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-DeviceID-Signature': signature,
          },
          body: payload,
        });
      } catch (err) {
        console.error(`Webhook delivery failed: ${hook.url}`, err.message);
      }
    }
  }
}

module.exports = IdentityGraph;